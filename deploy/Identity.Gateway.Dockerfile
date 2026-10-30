FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/Identity.Gateway/Identity.Gateway.csproj
RUN dotnet publish src/Identity.Gateway/Identity.Gateway.csproj -c Release -o /app/publish --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 5080
ENTRYPOINT ["dotnet", "Identity.Gateway.dll"]
