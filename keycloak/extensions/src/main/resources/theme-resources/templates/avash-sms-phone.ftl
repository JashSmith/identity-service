<#-- Passwordless SMS sign-in, step 1: the mobile number. Ships in the extension jar, so it works with every login theme. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("avashSmsTitle")}
    <#elseif section = "form">
        <form id="kc-sms-phone-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post"
              onsubmit="this.send.disabled = true; return true;">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcFormGroupLabelClass!}">
                    <label for="phone" class="${properties.kcFormLabelClass!} ${properties.kcLabelClass!}">
                        <span class="${properties.kcFormLabelTextClass!}">${msg("avashSmsPhoneLabel")}</span>
                    </label>
                </div>
                <span class="${properties.kcInputClass!}">
                    <input id="phone" name="phone" type="tel" inputmode="tel" autocomplete="tel" dir="ltr" autofocus required
                           maxlength="20" value="${(smsPhoneInput!'')}" placeholder="09121234567" />
                </span>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcFormActionGroupClass!}">
                    <button id="kc-sms-send" name="send" type="submit"
                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
                        ${msg("avashSmsSend")}
                    </button>
                </div>
            </div>
        </form>
    <#elseif section = "info">
        ${msg("avashSmsPhoneInfo")}
    </#if>
</@layout.registrationLayout>
