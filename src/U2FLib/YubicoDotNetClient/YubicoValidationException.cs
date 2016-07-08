using System;

namespace U2FLib.YubicoDotNetClient
{
    public class YubicoValidationException : Exception
    {
        public YubicoValidationException()
        {
        }

        public YubicoValidationException(string message) : base(message)
        {
        }

        public YubicoValidationException(string message, Exception inner) : base(message, inner)
        {
        }

        //protected YubicoValidationException(SerializationInfo info, StreamingContext context) : base(info, context)
        //{
        //}
    }
}
