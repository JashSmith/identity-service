<#-- SMS code entry (passwordless sign-in and second factor). Ships in the extension jar, so it works with every login theme. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        <#if smsPasswordless!false>${msg("avashSmsTitle")}<#else>${msg("avashSmsSecondFactorTitle")}</#if>
    <#elseif section = "form">
        <#if smsHasCode!false>
            <p id="kc-sms-sent" class="${properties.kcFormHelperTextClass!}" style="margin-block-end: 1rem; line-height: 1.8;">
                <#if smsPasswordless!false>${msg("avashSmsCodeSentIfRegistered", smsPhone!"")}<#else>${msg("avashSmsCodeSent", smsPhone!"")}</#if>
            </p>
        </#if>
        <form id="kc-sms-code-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <#if smsHasCode!false>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcFormGroupLabelClass!}">
                        <label for="code" class="${properties.kcFormLabelClass!} ${properties.kcLabelClass!}">
                            <span class="${properties.kcFormLabelTextClass!}">${msg("avashSmsCodeLabel")}</span>
                        </label>
                    </div>
                    <span class="${properties.kcInputClass!}">
                        <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" dir="ltr"
                               autofocus required maxlength="${smsCodeLength!6}" pattern="[0-9۰-۹٠-٩]*" />
                    </span>
                </div>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcFormActionGroupClass!}">
                        <button id="kc-sms-login" name="login" type="submit"
                                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">
                            ${msg("doLogIn")}
                        </button>
                    </div>
                </div>
            </#if>
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcFormActionGroupClass!}">
                    <button id="kc-sms-resend" name="resend" type="submit" formnovalidate data-wait="${smsResendIn!0}"
                            class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}">
                        ${msg("avashSmsResend")}
                    </button>
                    <#if smsPasswordless!false>
                        <button id="kc-sms-change" name="change-number" type="submit" formnovalidate
                                class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}">
                            ${msg("avashSmsChangeNumber")}
                        </button>
                    </#if>
                </div>
            </div>
        </form>
        <script>
            // Count down until another code may be requested; the server enforces the same wait.
            (function () {
                var button = document.getElementById("kc-sms-resend");
                var left = parseInt(button.getAttribute("data-wait"), 10) || 0;
                var label = button.textContent.trim();
                var digits = function (n) { return String(n).replace(/[0-9]/g, function (d) { return "۰۱۲۳۴۵۶۷۸۹"[d]; }); };
                var tick = function () {
                    if (left <= 0) { button.disabled = false; button.textContent = label; return; }
                    button.disabled = true;
                    button.textContent = label + " (" + digits(left) + ")";
                    left -= 1;
                    setTimeout(tick, 1000);
                };
                tick();
            })();
        </script>
    </#if>
</@layout.registrationLayout>
