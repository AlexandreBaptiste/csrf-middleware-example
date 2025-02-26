using Microsoft.AspNetCore.Antiforgery;

public class CsrfMiddleware
{
    private readonly IAntiforgery _antiforgery;
    private readonly RequestDelegate _next;
    private readonly ILogger<CsrfMiddleware> _logger;

    public CsrfMiddleware(RequestDelegate next, IAntiforgery antiforgery, ILogger<CsrfMiddleware> logger)
    {
        _antiforgery = antiforgery;
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;
        
        if (string.Equals(path, "/", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(path, "/index.html", StringComparison.OrdinalIgnoreCase))
        {
            var tokens = _antiforgery.GetAndStoreTokens(context);

            if(tokens == null)
            {
                _logger.LogError("Antiforgery tokens shouldn't be null");
                await _next(context);
            }
            
            context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken, new CookieOptions() { HttpOnly = false });
        }

        await _next(context);
    }
}

public static class CsrfMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestCsrf(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CsrfMiddleware>();
    }
}