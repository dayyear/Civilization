using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Text.RegularExpressions;
using System.Threading;


public class Web
{
    private readonly CookieContainer cookie;
    private const int timeout = 60000;

    private string su;

    private string retcode;
    private string servertime;
    private string pcid;
    private string nonce;
    private string pubkey;
    private string rsakv;
    private string is_openlock;
    private string showpin;
    private string exectime;

    private string uniqueid;
    private string userdomain;

    public Web()
    {
        cookie = new CookieContainer();
    }

    public Web(string file)
    {
        cookie = ReadCookiesFromDisk(file);
    }//Web

    /// <summary>
    /// 时间戳转DateTime
    /// new DateTime(1970,1,1,0,0,0,0,System.DateTimeKind.Utc).AddSeconds( 1492392740D ).ToLocalTime()          -->  2017/4/17 星期一 上午 9:32:20
    /// new DateTime(1970,1,1,0,0,0,0,System.DateTimeKind.Utc).AddMilliseconds( 1492392764559D ).ToLocalTime()  -->  2017/4/17 星期一 上午 9:32:44
    /// DateTime转时间戳
    /// (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds          -->  1492392740
    /// (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds     -->  1492392764559
    /// </summary>
    /// <param name="username"></param>
    public void PreLogin(string username)
    {
        // ReSharper disable once AssignNullToNotNullAttribute
        su = Convert.ToBase64String(Encoding.UTF8.GetBytes(HttpUtility.UrlEncode(username)));

        var rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
        var uri = string.Format("https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su={0}&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_={1}",
            HttpUtility.UrlEncode(su), rand);
        var response = Get(uri);
        File.WriteAllText("prelogin.htm", response);

        var pattern = @"sinaSSOController.preloginCallBack\({""retcode"":(?<retcode>.+?),""servertime"":(?<servertime>.+?),""pcid"":""(?<pcid>.+?)"",""nonce"":""(?<nonce>.+?)"",""pubkey"":""(?<pubkey>.+?)"",""rsakv"":""(?<rsakv>.+?)"",""is_openlock"":(?<is_openlock>.+?),""showpin"":(?<showpin>.+?),""exectime"":(?<exectime>.+?)}\)";
        var match = Regex.Match(response, pattern);
        if (!match.Success) throw new Exception("prelogin 匹配失败");


        retcode = match.Groups["retcode"].Value;
        servertime = match.Groups["servertime"].Value;
        pcid = match.Groups["pcid"].Value;
        nonce = match.Groups["nonce"].Value;
        pubkey = match.Groups["pubkey"].Value;
        rsakv = match.Groups["rsakv"].Value;
        is_openlock = match.Groups["is_openlock"].Value;
        showpin = match.Groups["showpin"].Value;
        exectime = match.Groups["exectime"].Value;

        Console.WriteLine("showpin: {0}", showpin);
    }//PreLogin

    /// <summary>
    /// post_data = {
    ///     "entry": "weibo",
    ///     "gateway": "1",
    ///     "from": "",
    ///     "savestate": "7",
    ///     "userticket": "1",
    ///     "vsnf": "1",
    ///     "service": "miniblog",
    ///     "encoding": "UTF-8",
    ///     "pwencode": "rsa2",
    ///     "sr": "1280*800",
    ///     "prelt": "529",
    ///     "url": "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
    ///     "rsakv": json_data["rsakv"],
    ///     "servertime": json_data["servertime"],
    ///     "nonce": json_data["nonce"],
    ///     "su": s_user_name,
    ///     "sp": s_pass_word,
    ///     "returntype": "TEXT",
    /// }
    /// 
    /// # login weibo.com
    /// login_url_1 = "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)&_=%d" % int(time.time())
    /// json_data_1 = self.session.post(login_url_1, data=post_data).json()
    /// </summary>
    /// <param name="password"></param>
    public void Login(string password)
    {
        // 1. 加密password
        var sp = GetPassword(password);

        // 2. login.php
        var uri = "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)";
        var postString = string.Format("entry=weibo&gateway=1&from=&savestate=7&useticket=1&pagerefer=&vsnf=1&su={0}&service=miniblog&servertime={1}&nonce={2}&pwencode=rsa2&rsakv={3}&sp={4}&sr=1920*1080&encoding=UTF-8&prelt=54&url=http%3A%2F%2Fweibo.com%2Fajaxlogin.php%3Fframelogin%3D1%26callback%3Dparent.sinaSSOController.feedBackUrlCallBack&returntype=META",
            HttpUtility.UrlEncode(su), servertime, nonce, rsakv, sp);
        var response = Post(uri, postString, "GBK");
        File.WriteAllText("login.htm", response, Encoding.GetEncoding("GBK"));

        var pattern = @"location.replace\('(.+?)'\)";
        var match = Regex.Match(response, pattern);
        if (!match.Success) throw new Exception("login 匹配失败");

        // 3. login, ajaxlogin.php
        uri = match.Groups[1].Value;
        response = Get(uri);
        File.WriteAllText("ajaxlogin.htm", response);

        pattern = "{\"uniqueid\":\"(?<uniqueid>.+?)\",\"userid\":.+?,\"displayname\":.+?,\"userdomain\":\"(?<userdomain>.+?)\"}";
        match = Regex.Match(response, pattern);
        if (!match.Success) throw new Exception("ajaxlogin 匹配失败");
        uniqueid = match.Groups["uniqueid"].Value;
        userdomain = match.Groups["userdomain"].Value;

        // 4. home
        //uri = string.Format("http://weibo.com/u/{0}/home{1}", uniqueid, userdomain);
        //response = Get(uri);
        //File.WriteAllText("home.htm", response);
    }//Login

    public void Zgwmw()
    {
        // 1. zgwmw
        var uri = "http://weibo.com/zgwmw?from=myfollow_all&is_all=1";
        Thread.Sleep(2000); var response = Get(uri);
        File.WriteAllText("zgwmw.htm", response);

        var pattern = @"mid=(?<mid>\d*)&name";
        var match = Regex.Match(response, pattern);
        if (!match.Success) throw new Exception("zgwmw 匹配失败");
        match = match.NextMatch();
        var mid = match.Groups["mid"].Value;

        // 2. watermark
        var rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
        // /aj/account/watermark?ajwvr=6&_t=0&__rnd=1492418715443
        uri = string.Format("http://weibo.com/aj/account/watermark?ajwvr=6&_t=0&__rnd={0}", rand);
        Thread.Sleep(2000); response = Get(uri);
        File.WriteAllText("watermark.htm", response);

        rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
        // /aj/v6/mblog/repost/small?ajwvr=6&mid=4097477676382817&d_expanded=on&expanded_status=1&__rnd=1492418715457
        uri = string.Format("http://weibo.com/aj/v6/mblog/repost/small?ajwvr=6&mid={0}&d_expanded=on&expanded_status=1&__rnd={1}", mid, rand);
        Thread.Sleep(2000); response = Get(uri);
        File.WriteAllText("small.htm", response);

        var domain = "100106";
        rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
        // /aj/v6/mblog/forward?ajwvr=6&domain=100106&__rnd=1492418720946
        uri = string.Format("http://weibo.com/aj/v6/mblog/forward?ajwvr=6&domain={0}&__rnd={1}", domain, rand);
        var location = "page_100106_home";
        var pdetail = "1001062119628851";
        // pic_src=&pic_id=&appkey=&mid=4097477676382817&style_type=1&mark=&reason=%E8%BD%AC%E5%8F%91%E5%BE%AE%E5%8D%9A&location=page_100106_home&pdetail=1001062119628851&module=&page_module_id=&refer_sort=&rank=0&rankid=&_t=0
        var postString = string.Format("pic_src=&pic_id=&appkey=&mid={0}&style_type=1&mark=&reason=%E8%BD%AC%E5%8F%91%E5%BE%AE%E5%8D%9A&location={1}&pdetail={2}&module=&page_module_id=&refer_sort=&rank=0&rankid=&_t=0",
            mid, HttpUtility.UrlEncode(location), pdetail);
        Thread.Sleep(2000); response = PostJson(uri, postString);
        File.WriteAllText("forward.htm", response);
    }//Zgwmw

    /// <summary>
    /// string = (str(servertime) + "\t" + str(nonce) + "\n" + str(self.pass_word)).encode("utf-8")
    /// public_key = rsa.PublicKey(int(pubkey, 16), int("10001", 16))
    /// password = rsa.encrypt(string, public_key)
    /// password = binascii.b2a_hex(password)
    /// return password.decode()
    /// </summary>
    /// <param name="password"></param>
    /// <returns></returns>
    private string GetPassword(string password)
    {
        var message = Encoding.UTF8.GetBytes(servertime + "\t" + nonce + "\n" + password);

        var modulus = new byte[pubkey.Length / 2];
        var exponent = new byte[] { 1, 0, 1 };
        for (var i = 0; i < modulus.Length; i++)
            modulus[i] = Convert.ToByte(pubkey.Substring(i * 2, 2), 16);

        byte[] encryptedBytes;
        using (var rsa = new RSACryptoServiceProvider())
        {
            var rsaKeyInfo = new RSAParameters { Modulus = modulus, Exponent = exponent };
            rsa.ImportParameters(rsaKeyInfo);
            encryptedBytes = rsa.Encrypt(message, false);
        }//RSA

        var sb = new StringBuilder();
        foreach (var b in encryptedBytes)
            sb.Append(b.ToString("x2"));

        return sb.ToString();
    }//GetPassword

    private string Get(string uri, string encoding = null)
    {
        string responseString;

        var request = (HttpWebRequest)WebRequest.Create(uri);
        request.CookieContainer = cookie;
        request.Timeout = timeout;

        using (var response = (HttpWebResponse)request.GetResponse())
        using (var stream = response.GetResponseStream())
        {
            if (stream == null)
                throw new ArgumentException("[stream] is null");
            if (response.CharacterSet == null)
                throw new ArgumentException("[response.CharacterSet] is null");
            using (var sr = new StreamReader(stream, Encoding.GetEncoding(encoding ?? response.CharacterSet)))
                responseString = sr.ReadToEnd();
        }

        return responseString;
    } //Get

    private string Post(string uri, string postString, string encoding = null)
    {
        string responseString;

        var request = (HttpWebRequest)WebRequest.Create(uri);
        request.CookieContainer = cookie;
        request.Timeout = timeout;

        // 设置POST数据
        var postByte = Encoding.UTF8.GetBytes(postString);
        request.Method = "POST";
        request.ContentType = "application/x-www-form-urlencoded";
        request.ContentLength = postByte.Length;
        using (var stream = request.GetRequestStream())
            stream.Write(postByte, 0, postByte.Length);

        // 发送POST
        using (var response = (HttpWebResponse)request.GetResponse())
        using (var stream = response.GetResponseStream())
        {
            if (stream == null)
                throw new ArgumentException("[stream] is null");
            if (response.CharacterSet == null)
                throw new ArgumentException("[response.CharacterSet] is null");
            using (var sr = new StreamReader(stream, Encoding.GetEncoding(encoding ?? response.CharacterSet)))
                responseString = sr.ReadToEnd();
        }

        return responseString;
    } //Post

    private string PostJson(string uri, string postString, string encoding = null)
    {
        string responseString;

        var request = (HttpWebRequest)WebRequest.Create(uri);
        request.CookieContainer = cookie;
        request.Timeout = timeout;

        // 设置POST数据
        var postByte = Encoding.UTF8.GetBytes(postString);
        request.Method = "POST";
        request.ContentType = "application/x-www-form-urlencoded";
        request.Headers.Add("X-Requested-With", "XMLHttpRequest");
        request.ContentLength = postByte.Length;
        using (var stream = request.GetRequestStream())
            stream.Write(postByte, 0, postByte.Length);

        // 发送POST
        using (var response = (HttpWebResponse)request.GetResponse())
        using (var stream = response.GetResponseStream())
        {
            if (stream == null)
                throw new ArgumentException("[stream] is null");
            if (response.CharacterSet == null)
                throw new ArgumentException("[response.CharacterSet] is null");
            using (var sr = new StreamReader(stream, Encoding.GetEncoding(encoding ?? response.CharacterSet)))
                responseString = sr.ReadToEnd();
        }

        return responseString;
    } //PostJson

    // ReSharper disable once UnusedMember.Local
    private void WriteCookiesToDisk(string file, CookieContainer cookieJar)
    {
        using (var stream = File.Create(file))
        {
            try
            {
                Console.Out.Write("Writing cookies to disk... ");
                var formatter = new BinaryFormatter();
                formatter.Serialize(stream, cookieJar);
                Console.Out.WriteLine("Done.");
            }
            catch (Exception e)
            {
                Console.WriteLine("Problem writing cookies to disk: " + e.GetType());
            }
        }
    }//WriteCookiesToDisk

    private CookieContainer ReadCookiesFromDisk(string file)
    {
        try
        {
            using (Stream stream = File.Open(file, FileMode.Open))
            {
                Console.Out.Write("Reading cookies from disk... ");
                BinaryFormatter formatter = new BinaryFormatter();
                Console.Out.WriteLine("Done.");
                return (CookieContainer)formatter.Deserialize(stream);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Problem reading cookies from disk: " + e.GetType());
            return new CookieContainer();
        }
    }//ReadCookiesFromDisk

}//class
