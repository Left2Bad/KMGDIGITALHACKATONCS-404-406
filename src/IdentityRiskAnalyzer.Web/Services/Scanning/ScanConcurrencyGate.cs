namespace IdentityRiskAnalyzer.Web.Services.Scanning;

// Single-instance coordination; the lease is held for the entire request-driven scan.
public sealed class ScanConcurrencyGate : IDisposable
{
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    public IDisposable? TryEnter() => _semaphore.Wait(0) ? new Lease(_semaphore) : null;

    public void Dispose() => _semaphore.Dispose();

    private sealed class Lease(SemaphoreSlim semaphore) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            semaphore.Release();
        }
    }
}
