<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("smsPhoneNumberTitle",realm.displayName)}
    <#elseif section = "form">
        <div class="${properties.kcFormGroupClass!}">
            <div class="${properties.kcLabelWrapperClass!}">
                <label class="${properties.kcLabelClass!}">${msg("smsPhoneNumberError")}</label>
            </div>
            <div class="${properties.kcInputWrapperClass!}">
                <div class="${properties.kcAlertClass!} ${properties.kcAlertErrorClass!}">
                    <span class="${properties.kcAlertTitleClass!}">${msg("error")}</span>
                    <span>${msg("smsPhoneNumberNotFound")}</span>
                </div>
            </div>
        </div>
        <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
            <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                <div class="${properties.kcFormOptionsWrapperClass!}">
                    <span><a href="${url.loginRestartFlowUrl}">${msg("backToLogin")?no_esc}</a></span>
                </div>
            </div>
        </div>
    <#elseif section = "info" >
        ${msg("smsPhoneNumberInstructions")}
    </#if>
</@layout.registrationLayout>
