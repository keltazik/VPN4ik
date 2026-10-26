try
{
    var passed = 0;
    await SubscriptionRegressionChecks.RunAsync((condition, name) =>
    {
        if (!condition) throw new InvalidOperationException(name);
        passed++;
    });
    Console.WriteLine($"PASS: {passed} subscription checks (synthetic data, no network requests).");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}
