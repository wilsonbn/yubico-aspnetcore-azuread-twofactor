namespace U2FLib.YubicoDotNetClient
{
    public enum YubicoResponseStatus
    {
        Empty,
        Ok,
        BadOtp,
        ReplayedOtp,
        BadSignature,
        MissingParameter,
        NoSuchClient,
        OperationNotAllowed,
        BackendError,
        NotEnoughAnswers,
        ReplayedRequest
    }
}
