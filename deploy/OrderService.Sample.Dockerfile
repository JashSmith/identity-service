FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore samples/OrderService.Sample/OrderService.Sample.csproj
RUN dotnet publish samples/OrderService.Sample/OrderService.Sample.csproj -c Release -o /app/publish --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 5180
ENTRYPOINT ["dotnet", "OrderService.Sample.dll"]
