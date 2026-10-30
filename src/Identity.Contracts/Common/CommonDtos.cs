namespace Identity.Contracts;

/// <summary>
/// Generic paginated response wrapper for list endpoints.
/// </summary>
/// <typeparam name="T">The type of item contained in the page.</typeparam>
/// <param name="Items">The items in the current page.</param>
/// <param name="Page">The current 1-based page number.</param>
/// <param name="PageSize">The page size limit requested.</param>
/// <param name="Total">The total count of items matching the query, if available.</param>
public sealed record PagedResponse<T>(IReadOnlyCollection<T> Items, int Page, int PageSize, int? Total = null);
