namespace Identity.Application;

/// <summary>Outcome of an operation without a value: success, or an <see cref="Application.Error"/>.</summary>
public sealed class Result
{
    private static readonly Result SuccessInstance = new(null);

    private Result(Error? error) => Error = error;

    /// <summary>The failure, or null on success.</summary>
    public Error? Error { get; }

    public bool IsSuccess => Error is null;

    public static Result Success() => SuccessInstance;

    public static Result Failure(Error error) => new(error ?? throw new ArgumentNullException(nameof(error)));

    public static implicit operator Result(Error error) => Failure(error);
}

/// <summary>Outcome of an operation that produces a <typeparamref name="T"/> on success.</summary>
public sealed class Result<T>
{
    private readonly T? _value;

    private Result(T? value, Error? error)
    {
        _value = value;
        Error = error;
    }

    /// <summary>The failure, or null on success.</summary>
    public Error? Error { get; }

    public bool IsSuccess => Error is null;

    /// <summary>The value; throws when the result is a failure.</summary>
    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException($"Cannot read the value of a failed result ({Error!.Code}).");

    public static Result<T> Success(T value) => new(value, null);

    public static Result<T> Failure(Error error) => new(default, error ?? throw new ArgumentNullException(nameof(error)));

    public static implicit operator Result<T>(T value) => Success(value);

    public static implicit operator Result<T>(Error error) => Failure(error);

    public Result<TOut> Map<TOut>(Func<T, TOut> map) =>
        IsSuccess ? Result<TOut>.Success(map(_value!)) : Result<TOut>.Failure(Error!);

    public async Task<Result<TOut>> BindAsync<TOut>(Func<T, Task<Result<TOut>>> next) =>
        IsSuccess ? await next(_value!) : Result<TOut>.Failure(Error!);
}
