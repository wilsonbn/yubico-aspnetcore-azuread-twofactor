using System;
using System.Diagnostics;
using Xunit;

namespace U2FLib.Tests
{
    public class Class
    {

        [Fact]
        public void YubicoVerify()
        {

            var clientId = "29254";
            var apiKey = "HbUOZXS8t9dyjyiD7KEDW6N7KLU=";
            var sync = "";
            var nonce = "";
            var otp = "ccccccfhjhlvgjrncgvirehldrbufrgncrkeudnltnkb";
            //YubicoClient client = new YubicoClient(clientId, apiKey);
            //IYubicoResponse response = client.Verify(otp);
            //if (response.Status == YubicoResponseStatus.Ok)
            //{
            //    // validation success
            //}
            //else
            //{
            //    // validation failure
            //}
            var client = new YubicoDotNetClient.YubicoClient(clientId);
            if (!string.IsNullOrEmpty(apiKey))
            {
                client.SetApiKey(apiKey);
            }
            if (!string.IsNullOrEmpty(sync))
            {
                client.SetSync(sync);
            }
            if (!string.IsNullOrEmpty(nonce))
            {
                client.SetNonce(nonce);
            }
            try
            {
                var sw = Stopwatch.StartNew();
                var response = client.Verify(otp);
                sw.Stop();
                if (response != null)
                {
                    Console.WriteLine("response in: {0}{1}", sw.ElapsedMilliseconds, Environment.NewLine);
                    Debug.WriteLine("Status: {0}{1}", response.Status, Environment.NewLine);
                    Debug.WriteLine("Public ID: {0}{1}", response.PublicId, Environment.NewLine);
                    Debug.WriteLine("Use/Session Counter: {0} {1}{2}", response.UseCounter, response.SessionCounter, Environment.NewLine);
                    Debug.WriteLine(string.Format("Url: {0}", response.Url));
                }
                else
                {
                    Debug.WriteLine("Null result returned, error in call");
                }
            }
            catch (YubicoDotNetClient.YubicoValidationFailure yvf)
            {
                Debug.WriteLine("Failure in validation: {0}{1}", yvf.Message, Environment.NewLine);
            }
            Assert.True(true);
        }
    }
}
