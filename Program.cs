using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            string username, password;
            if (args.Count() >= 2)
            {
                username = args[0];
                password = args[1];
                Console.WriteLine("username: {0}", username);
                Console.WriteLine("password: {0}", password);
            }
            else
            {
                Console.Write("username: ");
                username = Console.ReadLine();
                Console.Write("password: ");
                password = Console.ReadLine();
            }

            if (args.Count() >= 3)
            {
                var web = new Web(args[2]);
                web.Zgwmw();
            }
            else
            {
                var web = new Web();
                var showpin = web.PreLogin(username);
                Console.WriteLine("showpin: {0}", showpin);
                if ("1".Equals(showpin))
                {
                    Process.Start(web.Pin());
                    Console.Write("door: ");
                    var door = Console.ReadLine();
                    web.Login(password, door);
                }
                else
                    web.Login(password);
                web.Zgwmw();
            }
        }//Main
    }//class
}//namespace
