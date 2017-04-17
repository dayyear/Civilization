using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Civilization
{
    class Program
    {
        static void Main(string[] args)
        {
            var web = new Web();

            Console.Write("username:");
            var username = "15589559@qq.com";//Console.ReadLine();
            web.PreLogin(username);

            Console.Write("password:");
            var password = "orange1234";// Console.ReadLine();
            web.Login(password);

            web.Zgwmw();
        }
    }
}
