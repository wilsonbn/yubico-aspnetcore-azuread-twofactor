using System;
using System.Collections.Generic;
using System.IO;

namespace U2FLib.YubicoDotNetClient
{
    public sealed class YubicoResponse : IYubicoResponse
    {
        public string H { get; }
        public string T { get; }
        public YubicoResponseStatus Status { get; }
        public int Timestamp { get; }
        public int SessionCounter { get; }
        public int UseCounter { get; }
        public string Sync { get; }
        public string Otp { get; }
        public string Nonce { get; }
        public IEnumerable<KeyValuePair<string, string>> ResponseMap { get; }
        public string PublicId { get; }
        public string Url { get; }

        public YubicoResponse(string response, string url)
        {
            var reader = new StringReader(response);
            string line;

            var responseMap = new SortedDictionary<string, string>();
            ResponseMap = responseMap;

            while ((line = reader.ReadLine()) != null)
            {
                var unhandled = false;
                var parts = line.Split(new[] { '=' }, 2);

                switch (parts[0])
                {
                    case "h":
                        H = parts[1];
                        break;
                    case "t":
                        T = parts[1];
                        break;
                    case "status":
                        var statusCode = parts[1];
                        if (statusCode.Equals("EMPTY", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.Empty;
                        }
                        else if (statusCode.Equals("OK", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.Ok;
                        }
                        else if (statusCode.Equals("BAD_OTP", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.BadOtp;
                        }
                        else if (statusCode.Equals("REPLAYED_OTP", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.ReplayedOtp;
                        }
                        else if (statusCode.Equals("BAD_SIGNATURE", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.BadSignature;
                        }
                        else if (statusCode.Equals("MISSING_PARAMETER", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.MissingParameter;
                        }
                        else if (statusCode.Equals("NO_SUCH_CLIENT", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.NoSuchClient;
                        }
                        else if (statusCode.Equals("OPERATION_NOT_ALLOWED", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.OperationNotAllowed;
                        }
                        else if (statusCode.Equals("BACKEND_ERROR", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.BackendError;
                        }
                        else if (statusCode.Equals("NOT_ENOUGH_ANSWERS", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.NotEnoughAnswers;
                        }
                        else if (statusCode.Equals("REPLAYED_REQUEST", StringComparison.OrdinalIgnoreCase))
                        {
                            Status = YubicoResponseStatus.ReplayedRequest;
                        }
                        else
                        {
                            throw new ArgumentException("Response doesn't look like a validation response.");
                        }
                        break;
                    case "timestamp":
                        Timestamp = int.Parse(parts[1]);
                        break;
                    case "sessioncounter":
                        SessionCounter = int.Parse(parts[1]);
                        break;
                    case "sessionuse":
                        UseCounter = int.Parse(parts[1]);
                        break;
                    case "sl":
                        Sync = parts[1];
                        break;
                    case "otp":
                        Otp = parts[1];
                        break;
                    case "nonce":
                        Nonce = parts[1];
                        break;
                    default:
                        unhandled = true;
                        break;
                }
                if (!unhandled)
                {
                    responseMap.Add(parts[0], parts[1]);
                }
            }
            if (Status == YubicoResponseStatus.Empty)
            {
                throw new ArgumentException("Response doesn't look like a validation response.");
            }

            if (Otp != null && Otp.Length > 32 && YubicoClient.IsOtpValidFormat(Otp))
            {
                PublicId = Otp.Substring(0, Otp.Length - 32);
            }

            Url = url;
        }
    }
}
