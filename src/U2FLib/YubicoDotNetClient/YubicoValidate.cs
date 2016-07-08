using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace U2FLib.YubicoDotNetClient
{
    public sealed class YubicoValidate
    {
        public static IYubicoResponse Validate(IEnumerable<string> urls, string userAgent)
        {
            var tasks = new List<Task<IYubicoResponse>>();
            var cancellation = new CancellationTokenSource();

            foreach (var url in urls)
            {
                var thisUrl = url;
                var task = new Task<IYubicoResponse>(() => DoVerify(thisUrl, userAgent), cancellation.Token);
                task.ContinueWith(t => { }, TaskContinuationOptions.OnlyOnFaulted);
                tasks.Add(task);
                task.Start();
            }

            while (tasks.Count != 0)
            {
                // TODO: handle exceptions from the verify task. Better to be able to propagate cause for error.
                var completed = Task.WaitAny(tasks.Cast<Task>().ToArray());
                var task = tasks[completed];
                tasks.Remove(task);
                if (task.Result != null)
                {
                    cancellation.Cancel();
                    return task.Result;
                }
            }

            return null;
        }

        private static IYubicoResponse DoVerify(string url, string userAgent)
        {

            var httpClient = new HttpClient();


            if (userAgent == null)
            {
                httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "YubicoDotNetClient version:" + Assembly.GetEntryAssembly().GetName().Version);
            }
            else
            {
                httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", userAgent);
            }

            //httpClient.Timeout = new TimeSpan(15000);

            var httpClientResponse = httpClient.GetAsync(new Uri(url)).Result;

            httpClientResponse.EnsureSuccessStatusCode();
            var rawResponse = httpClientResponse.Content.ReadAsStreamAsync().Result;
            using (var dataStream = rawResponse)
            {
                if (dataStream != null)
                {
                    using (var reader = new StreamReader(dataStream))
                    {
                        IYubicoResponse response;

                        try
                        {
                            response = new YubicoResponse(reader.ReadToEnd(), url);
                        }
                        catch (ArgumentException)
                        {
                            return null;
                        }

                        if (response.Status == YubicoResponseStatus.ReplayedRequest)
                        {
                            //throw new YubicoValidationException("Replayed request, this otp & nonce combination has been seen before.");
                            return null;
                        }

                        return response;
                    }
                }
            }

            throw new YubicoValidationException();
        }
    }
}
