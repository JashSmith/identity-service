<#--
  Avash branding of an application's login page. keycloak.v2 calls this macro inside the login card; when the
  application's client has iam.login.mode=branded, it adds the application's logo, title and colour.
  Values are written by the Identity Gateway, which validates them (plain text, https logo, #RRGGBB with enough
  contrast). They are still checked here and HTML-escaped by FreeMarker, so a bad attribute cannot inject markup.
-->
<#macro content>
  <#if client?? && ((client.getAttribute("iam.login.mode"))!"") == "branded">
    <#assign avashColor = (client.getAttribute("iam.login.primary_color"))!"">
    <#assign avashLogo = (client.getAttribute("iam.login.logo_url"))!"">
    <#assign avashTitle = (client.getAttribute("iam.login.title"))!"">
    <#assign avashSubtitle = (client.getAttribute("iam.login.subtitle"))!"">
    <#assign avashBackground = (client.getAttribute("iam.login.background"))!"pattern">
    <#if avashColor?matches("^#[0-9a-fA-F]{6}$")>
      <style>:root { --avash-brand: ${avashColor}; }</style>
    </#if>
    <div class="avash-brand" data-background="${avashBackground?matches("^(pattern|plain|gradient)$")?then(avashBackground, "pattern")}">
      <#if avashLogo?starts_with("https://")>
        <img class="avash-brand__logo" src="${avashLogo}" alt="" referrerpolicy="no-referrer">
      </#if>
      <#if avashTitle?has_content>
        <p class="avash-brand__title">${avashTitle}</p>
      </#if>
      <#if avashSubtitle?has_content>
        <p class="avash-brand__subtitle">${avashSubtitle}</p>
      </#if>
    </div>
  </#if>
</#macro>
