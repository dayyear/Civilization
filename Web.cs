using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;

namespace Civilization
{
    /// <summary>
    /// 时间戳转DateTime
    /// new DateTime(1970,1,1,0,0,0,0,System.DateTimeKind.Utc).AddSeconds( 1492392740D ).ToLocalTime()          -->  2017/4/17 星期一 上午 9:32:20
    /// new DateTime(1970,1,1,0,0,0,0,System.DateTimeKind.Utc).AddMilliseconds( 1492392764559D ).ToLocalTime()  -->  2017/4/17 星期一 上午 9:32:44
    /// DateTime转时间戳
    /// (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds          -->  1492392740
    /// (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds     -->  1492392764559
    /// </summary>
    public class Web
    {
        private readonly CookieContainer cookie;
        private readonly string cookieFile;
        private const int timeout = 60000;

        private string su;
        private string servertime;
        private string nonce;
        private string pubkey;
        private string rsakv;
        private string pcid;

        public Web()
        {
            cookieFile = "cookie";
            cookie = new CookieContainer();
        }

        public Web(string cookieFile)
        {
            this.cookieFile = cookieFile;
            cookie = ReadCookiesFromDisk(cookieFile);
        }//Web

        public string PreLogin(string username)
        {
            // 1. GET /sso/prelogin.php
            su = Convert.ToBase64String(Encoding.UTF8.GetBytes(HttpUtility.UrlEncode(username)));
            var rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
            var uri = string.Format("https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su={0}&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_={1}",
                HttpUtility.UrlEncode(su), rand);
            Console.WriteLine("GET /sso/prelogin.php");
            var response = Get(uri);
            Thread.Sleep(1000);
            File.WriteAllText("prelogin.htm", response);

            // 2. Obtain servertime, nonce, pubkey, rsakv and showpin
            var pattern = @"sinaSSOController.preloginCallBack\({""retcode"":(?<retcode>.+?),""servertime"":(?<servertime>.+?),""pcid"":""(?<pcid>.+?)"",""nonce"":""(?<nonce>.+?)"",""pubkey"":""(?<pubkey>.+?)"",""rsakv"":""(?<rsakv>.+?)"",""is_openlock"":(?<is_openlock>.+?),""showpin"":(?<showpin>.+?),""exectime"":(?<exectime>.+?)}\)";
            var match = Regex.Match(response, pattern);
            if (!match.Success)
                throw new Exception("prelogin 匹配失败");
            servertime = match.Groups["servertime"].Value;
            nonce = match.Groups["nonce"].Value;
            pubkey = match.Groups["pubkey"].Value;
            rsakv = match.Groups["rsakv"].Value;
            pcid = match.Groups["pcid"].Value;
            var showpin = match.Groups["showpin"].Value;

            return showpin;
        }//PreLogin

        public string Pin()
        {
            var rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            var uri = string.Format("http://login.sina.com.cn/cgi/pin.php?r={0}&s=0&p={1}",
                rand, pcid);
            Console.WriteLine("GET /cgi/pin.php");
            var response = GetBytes(uri);
            Thread.Sleep(1000);
            var pinFile = "pin.bmp";
            File.WriteAllBytes(pinFile, response);

            return pinFile;
        }//Pin

        public void Login(string password, string door = null)
        {
            // 1. 加密password
            var sp = GetPassword(password);

            // 2. login.php
            var uri = "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)";
            var postString = string.Format("entry=weibo&gateway=1&from=&savestate=7&useticket=1&pagerefer=&vsnf=1&su={0}&service=miniblog&servertime={1}&nonce={2}&pwencode=rsa2&rsakv={3}&sp={4}&sr=1920*1080&encoding=UTF-8&prelt=54&url=http%3A%2F%2Fweibo.com%2Fajaxlogin.php%3Fframelogin%3D1%26callback%3Dparent.sinaSSOController.feedBackUrlCallBack&returntype=META",
                HttpUtility.UrlEncode(su), servertime, nonce, rsakv, sp);
            if (!string.IsNullOrWhiteSpace(door))
                postString += string.Format("&pcid={0}&door={1}", pcid, door);
            Console.WriteLine("POST /sso/login.php");
            var response = Post(uri, postString, "GBK");
            Thread.Sleep(1000);
            File.WriteAllText("login.htm", response, Encoding.GetEncoding("GBK"));

            var pattern = @"location.replace\('(?<uri>.+?)'\)";
            var match = Regex.Match(response, pattern);
            if (!match.Success)
                throw new Exception("login 匹配失败");
            uri = match.Groups["uri"].Value;

            // 3. login, ajaxlogin.php
            Console.WriteLine("GET /wbsso/login");
            Console.WriteLine("GET /ajaxlogin.php");
            response = Get(uri);
            Thread.Sleep(1000);
            File.WriteAllText("ajaxlogin.htm", response);

            pattern = "{\"uniqueid\":\"(?<uniqueid>.+?)\",\"userid\":.+?,\"displayname\":.+?,\"userdomain\":\"(?<userdomain>.+?)\"}";
            match = Regex.Match(response, pattern);
            if (!match.Success)
                throw new Exception("ajaxlogin 匹配失败");
        }//Login

        public void Zgwmw()
        {
            // 1. zgwmw
            var uri = "http://weibo.com/zgwmw?from=myfollow_all&is_all=1";
            Console.WriteLine("GET /zgwmw");
            var response = Get(uri);
            Thread.Sleep(1000);
            File.WriteAllText("zgwmw.htm", response);

            var pattern = @"\$CONFIG\['uid'\]='(?<uid>\d*)';";
            var match = Regex.Match(response, pattern);
            if (!match.Success)
                throw new Exception("uid 匹配失败");
            var uid = match.Groups["uid"].Value;

            pattern = @"mid=(?<mid>\d*)&name";
            var matches = Regex.Matches(response, pattern);
            if (matches.Count <= 0)
                throw new Exception("mid 匹配失败");
            var midList = (from Match _match in matches select _match.Groups["mid"].Value).ToList();

            // 2. profile
            uri = string.Format("http://weibo.com/{0}/profile?rightmod=1&wvr=6&mod=personnumber&is_all=1", uid);
            Console.WriteLine("GET /{0}/profile", uid);
            response = Get(uri);
            Thread.Sleep(1000);
            File.WriteAllText("MyWeibo.htm", response);

            // 3. forward
            foreach (var mid in midList.Where(mid => !response.Contains(mid)))
                Forward(mid);
        }//Zgwmw

        private void Forward(string mid)
        {
            var domain = "100106";
            var rand = (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalMilliseconds;
            var uri = string.Format("http://weibo.com/aj/v6/mblog/forward?ajwvr=6&domain={0}&__rnd={1}", domain, rand);
            var location = "page_100106_home";
            var pdetail = "1001062119628851";
            var postString = string.Format("pic_src=&pic_id=&appkey=&mid={0}&style_type=1&mark=&reason=%E8%BD%AC%E5%8F%91%E5%BE%AE%E5%8D%9A&location={1}&pdetail={2}&module=&page_module_id=&refer_sort=&rank=0&rankid=&_t=0",
                mid, HttpUtility.UrlEncode(location), pdetail);
            Console.WriteLine("POST /aj/v6/mblog/forward: {0}", mid);
            var response = PostZgwmw(uri, postString);
            Thread.Sleep(10000);
            File.WriteAllText(string.Format("forward{0}.htm", mid), response);
        }//Forward

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
            WriteCookiesToDisk(cookieFile, cookie);

            return responseString;
        } //Get

        private byte[] GetBytes(string uri)
        {
            byte[] responseBytes;
            var buffer = new byte[4096];

            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.CookieContainer = cookie;
            request.Timeout = timeout;

            using (var response = (HttpWebResponse)request.GetResponse())
            using (var stream = response.GetResponseStream())
            using (var ms = new MemoryStream())
            {
                if (stream == null)
                    throw new ArgumentException("[stream] is null");
                var count = 0;
                do
                {
                    count = stream.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, count);

                } while (count != 0);
                responseBytes = ms.ToArray();
            }
            WriteCookiesToDisk(cookieFile, cookie);

            return responseBytes;
        } //GetBytes

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
            WriteCookiesToDisk(cookieFile, cookie);

            return responseString;
        } //Post

        private string PostZgwmw(string uri, string postString, string encoding = null)
        {
            string responseString;

            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.CookieContainer = cookie;
            request.Timeout = timeout;

            // 设置POST数据
            var postByte = Encoding.UTF8.GetBytes(postString);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Referer = "http://weibo.com/zgwmw?from=myfollow_all&is_all=1";
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
            WriteCookiesToDisk(cookieFile, cookie);

            return responseString;
        } //PostZgwmw

        private static void WriteCookiesToDisk(string file, CookieContainer cookieJar)
        {
            using (var stream = File.Create(file))
            {
                try
                {
                    //Console.Out.Write("Writing cookies to disk... ");
                    var formatter = new BinaryFormatter();
                    formatter.Serialize(stream, cookieJar);
                    //Console.Out.WriteLine("Done.");
                }
                catch (Exception e)
                {
                    Console.WriteLine("Problem writing cookies to disk: " + e.GetType());
                }
            }
        }//WriteCookiesToDisk

        private static CookieContainer ReadCookiesFromDisk(string file)
        {
            try
            {
                using (Stream stream = File.Open(file, FileMode.Open))
                {
                    //Console.Out.Write("Reading cookies from disk... ");
                    var formatter = new BinaryFormatter();
                    //Console.Out.WriteLine("Done.");
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
}//namespace
