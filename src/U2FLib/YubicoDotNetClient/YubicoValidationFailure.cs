using System;

namespace U2FLib.YubicoDotNetClient
{
    public class YubicoValidationFailure : Exception
    {
        public YubicoValidationFailure()
        {
        }

        public YubicoValidationFailure(string message) : base(message)
        {
        }

        public YubicoValidationFailure(string message, Exception inner) : base(message, inner)
        {
        }

        //protected YubicoValidationFailure(SerializationInfo info, StreamingContext context) : base(info, context)
        //{
        //}
    }
}
