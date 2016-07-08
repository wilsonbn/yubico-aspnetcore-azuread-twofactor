using System.Collections.Generic;

namespace U2FLib.YubicoDotNetClient
{
    public interface IYubicoResponse
    {
        /// <summary>
        /// Get the servers signature of the response.
        /// </summary>
        /// <returns>Base64 of hmac-sha1 of the response concatenated as url</returns>
        string H { get; }

        /// <summary>
        /// Get the servers response of the timestamp.
        /// </summary>
        /// <returns>timestamp in UTC</returns>
        string T { get; }

        /// <summary>
        /// The response status
        /// </summary>
        /// <returns>status of the response</returns>
        YubicoResponseStatus Status { get; }

        /// <summary>
        /// The YubiKey internal timestamp when OTP was generated
        /// </summary>
        /// <returns>YubiKey internal 8hz timestamp</returns>
        int Timestamp { get; }

        /// <summary>
        /// The YubiKey internal sessionCounter
        /// </summary>
        /// <returns>the YubiKey session counter, counting up for each key press</returns>
        int SessionCounter { get; }

        /// <summary>
        /// The YubiKey internal useCounter
        /// </summary>
        /// <returns>the YubiKey use counter, counts up for each powerup</returns>
        int UseCounter { get; }

        /// <summary>
        /// The Syncronization achieved
        /// </summary>
        /// <returns>syncronization achieved in percent</returns>
        string Sync { get; }

        /// <summary>
        /// The OTP asked about
        /// </summary>
        /// <returns>the OTP that the server is returning a result for</returns>
        string Otp { get; }

        /// <summary>
        /// The nonce that was sent in the request
        /// </summary>
        /// <returns>the nonce that was sent to the server in the request</returns>
        string Nonce { get; }

        /// <summary>
        /// A map of all results returned
        /// </summary>
        /// <returns>map of the results returned from the server</returns>
        IEnumerable<KeyValuePair<string, string>> ResponseMap { get; }

        /// <summary>
        /// The publicId of the OTP this response is about
        /// </summary>
        /// <returns>the publicId for the OTP</returns>
        string PublicId { get; }

        /// <summary>
        /// The URL used to get this response
        /// </summary>
        /// <returns>the URL where this response came from</returns>
        string Url { get; }
    }
}
