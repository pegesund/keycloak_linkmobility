<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("phoneAuthTitle",realm.displayName)}
    <#elseif section = "form">
        <form onsubmit="login.disabled = true; return true;" id="kc-phone-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="phoneNumber" class="${properties.kcLabelClass!}">${msg("phoneNumberLabel")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="tel" id="phoneNumber" name="phoneNumber" class="${properties.kcInputClass!}" autocomplete="tel" autofocus />
                </div>
            </div>
            <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input name="login" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
                </div>
            </div>
        </form>
    <#elseif section = "info" >
        ${msg("phoneAuthInstruction")}
    </#if>
</@layout.registrationLayout>
