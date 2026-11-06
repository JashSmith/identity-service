using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Identity.Application;
using Identity.Application.Users;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>The mobile number Keycloak's SMS sign-in finds users by: normalised, unique, only through PhoneNumber.</summary>
public sealed class UserPhoneNumberTests
{
    private sealed class FakeKeycloak(string? otherUserWithPhone) : HttpMessageHandler
    {
        public JsonNode? Written { get; private set; }
        public string? Query { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });
            if (path.EndsWith("/admin/realms/avash/users", StringComparison.Ordinal) && request.Method == HttpMethod.Get)
            {
                Query = Uri.UnescapeDataString(request.RequestUri.Query);
                return Json(otherUserWithPhone is null
                    ? Array.Empty<object>()
                    : [new { id = otherUserWithPhone, username = "other", attributes = new Dictionary<string, string[]> { ["phone_number"] = ["+989121234567"] } }]);
            }
            if (path.EndsWith("/users/u1", StringComparison.Ordinal) && request.Method == HttpMethod.Get)
                return Json(new { id = "u1", username = "sara", enabled = true, attributes = Written?["attributes"] ?? new JsonObject() });
            if (path.EndsWith("/users/u1", StringComparison.Ordinal) && request.Method == HttpMethod.Put)
            {
                Written = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct));
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };
    }

    private static KeycloakUserProvisioner Provisioner(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "avash", AdminClientSecret = "s" });
        return new KeycloakUserProvisioner(new HttpClient(kc), options, new KeycloakAdminTokenProvider(new HttpClient(kc), options));
    }

    [Fact]
    public async Task The_number_is_stored_normalised_and_returned()
    {
        var kc = new FakeKeycloak(otherUserWithPhone: null);

        var updated = await Provisioner(kc).UpdateUserAsync("u1", new UpdateUserRequest(null, null, null, null, PhoneNumber: "۰۹۱۲ ۱۲۳ ۴۵۶۷"),
            CancellationToken.None);

        Assert.True(updated.IsSuccess);
        Assert.Equal("+989121234567", kc.Written!["attributes"]!["phone_number"]![0]!.GetValue<string>());
        Assert.Equal("+989121234567", updated.Value.PhoneNumber);
        Assert.Contains("q=phone_number:+989121234567", kc.Query);
    }

    [Fact]
    public async Task A_number_of_another_user_is_refused()
    {
        var kc = new FakeKeycloak(otherUserWithPhone: "u2");

        var refused = await Provisioner(kc).UpdateUserAsync("u1", new UpdateUserRequest(null, null, null, null, PhoneNumber: "09121234567"),
            CancellationToken.None);

        Assert.Equal("user.phone_number_taken", refused.Error!.Code);
        Assert.Equal(ErrorKind.Conflict, refused.Error.Kind);
        Assert.Null(kc.Written);
    }

    [Fact]
    public async Task The_users_own_number_may_be_saved_again_and_an_empty_number_removes_it()
    {
        var kc = new FakeKeycloak(otherUserWithPhone: "u1");
        var provisioner = Provisioner(kc);

        Assert.True((await provisioner.UpdateUserAsync("u1", new UpdateUserRequest(null, null, null, null, PhoneNumber: "09121234567"),
            CancellationToken.None)).IsSuccess);
        var removed = await provisioner.UpdateUserAsync("u1", new UpdateUserRequest(null, null, null, null, PhoneNumber: ""), CancellationToken.None);

        Assert.True(removed.IsSuccess);
        Assert.Null(kc.Written!["attributes"]!["phone_number"]);
        Assert.Null(removed.Value.PhoneNumber);
    }

    [Fact]
    public void The_number_can_only_be_set_through_PhoneNumber()
    {
        Assert.True(ProtectedUserAttributes.IsProtected("phone_number"));
        Assert.True(ProtectedUserAttributes.IsProtected(" Phone_Number "));
        var generic = new UpdateUserRequest(null, null, null, null, Attributes: new Dictionary<string, string[]> { ["phone_number"] = ["+989121234567"] });
        Assert.False(new UpdateUserRequestValidator().Validate(generic).IsValid);
    }

    [Theory]
    [InlineData("09121234567", true)]
    [InlineData("+98 912 123 4567", true)]
    [InlineData("02112345678", false)]
    [InlineData("0912", false)]
    public void Only_iranian_mobile_numbers_are_accepted(string phone, bool valid)
    {
        Assert.Equal(valid, new UpdateUserRequestValidator().Validate(new UpdateUserRequest(null, null, null, null, PhoneNumber: phone)).IsValid);
        Assert.Equal(valid, new CreateUserRequestValidator().Validate(new CreateUserRequest("sara", null, null, null, true, null, null, phone)).IsValid);
    }
}
