using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using JGUZDV.BundId.SAMLProxy.SAML2;
using Microsoft.AspNetCore.Authentication;
using Sustainsys.Saml2.AspNetCore;
using Sustainsys.Saml2.AspNetCore.Events;
using System.Xml;
using System.Xml.Linq;

namespace JGUZDV.BundId.SAMLProxy;

public class BundIDSaml2AuthenticationEvents : Saml2Events
{
    public override async Task AuthnRequestGeneratedAsync(AuthnRequestGeneratedContext context)
    {
        await base.AuthnRequestGeneratedAsync(context);

        context.AuthnRequest.Extensions ??= new();


        var fakeWrapper = new XmlDocument();
        var akdbElement = fakeWrapper.CreateElement("akdb", "AuthenticationRequest", "https://www.akdb.de/request/2018/09");
        akdbElement.SetAttribute("EnableStatusDetail", "true");
        akdbElement.SetAttribute("Version", "2");

        var authnMethods = akdbElement.AppendChild(fakeWrapper.CreateElement("akdb", "AuthnMethods", "https://www.akdb.de/request/2018/09"));
        authnMethods!.AddAuthnMethod("Benutzername", true);
        authnMethods.AddAuthnMethod("eID", true);
        authnMethods.AddAuthnMethod("eIDAS", true);
        authnMethods.AddAuthnMethod("Elster", true);
        authnMethods.AddAuthnMethod("FINK", true);

        var requestedAttributes = akdbElement.AppendChild(fakeWrapper.CreateElement("akdb", "RequestedAttributes", "https://www.akdb.de/request/2018/09"));
        requestedAttributes!.AddAttribute(BundIdAttributes.BPK2, true);
        requestedAttributes.AddAttribute(BundIdAttributes.Gender, false);
        requestedAttributes.AddAttribute(BundIdAttributes.PersonalTitle, false);
        requestedAttributes.AddAttribute(BundIdAttributes.GivenName, true);
        requestedAttributes.AddAttribute(BundIdAttributes.Surname, true);
        requestedAttributes.AddAttribute(BundIdAttributes.Birthdate, true);
        requestedAttributes.AddAttribute(BundIdAttributes.BirthName, false);
        requestedAttributes.AddAttribute(BundIdAttributes.PlaceOfBirth, true);
        requestedAttributes.AddAttribute(BundIdAttributes.PostalCode, true);
        requestedAttributes.AddAttribute(BundIdAttributes.LocalityName, true);
        requestedAttributes.AddAttribute(BundIdAttributes.PostalAddress, true);
        requestedAttributes.AddAttribute(BundIdAttributes.Country, true);
        requestedAttributes.AddAttribute(BundIdAttributes.Nationality, false);
        requestedAttributes.AddAttribute(BundIdAttributes.Mail, true);
        requestedAttributes.AddAttribute(BundIdAttributes.EIDCitizenQaaLevel, false);

        var akdbDisplay = akdbElement.AppendChild(fakeWrapper.CreateElement("akdb", "DisplayInformation", "https://www.akdb.de/request/2018/09"));
        akdbDisplay!.InnerXml = """
            <classic-ui:Version xmlns:classic-ui="https://www.akdb.de/request/2018/09/classic-ui/v1">
                <classic-ui:OrganizationDisplayName>
                    <![CDATA[Johannes Gutenberg-Universität Mainz]]>
                </classic-ui:OrganizationDisplayName>
                <classic-ui:Lang>de</classic-ui:Lang>
            </classic-ui:Version>
            """;

        context.AuthnRequest.Extensions.Contents.Add(akdbElement);

        context.AuthnRequest.Extensions.Contents.Add(XElement.Parse($"""
        <akdb:AuthenticationRequest xmlns:akdb="https://www.akdb.de/request/2018/09" EnableStatusDetail="true" Version="2">
            <akdb:AuthnMethods>
                <akdb:Authega><akdb:Enabled>true</akdb:Enabled></akdb:Authega>
                <akdb:Benutzername><akdb:Enabled>true</akdb:Enabled></akdb:Benutzername>
                <akdb:Diia><akdb:Enabled>true</akdb:Enabled></akdb:Diia>
                <akdb:eID><akdb:Enabled>true</akdb:Enabled></akdb:eID>
                <akdb:eIDAS><akdb:Enabled>true</akdb:Enabled></akdb:eIDAS>
                <akdb:Elster><akdb:Enabled>true</akdb:Enabled></akdb:Elster>
                <akdb:FINK><akdb:Enabled>true</akdb:Enabled></akdb:FINK>
            </akdb:AuthnMethods>
            <akdb:RequestedAttributes>
                <akdb:RequestedAttribute Name="{BundIdAttributes.BPK2}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Gender}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PersonalTitle}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.GivenName}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Surname}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Birthdate}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.BirthName}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PlaceOfBirth}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PostalCode}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.LocalityName}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.PostalAddress}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Country}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Nationality}" RequiredAttribute="false" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.Mail}" RequiredAttribute="true" />
                <akdb:RequestedAttribute Name="{BundIdAttributes.EIDCitizenQaaLevel}" RequiredAttribute="false" />
            </akdb:RequestedAttributes>
            <akdb:DisplayInformation>
                <classic-ui:Version xmlns:classic-ui="https://www.akdb.de/request/2018/09/classic-ui/v1">
                    <classic-ui:OrganizationDisplayName>
                        <![CDATA[Johannes Gutenberg-Universität Mainz]]>
                    </classic-ui:OrganizationDisplayName>
                    <classic-ui:Lang>de</classic-ui:Lang>
                </classic-ui:Version>
            </akdb:DisplayInformation>
        </akdb:AuthenticationRequest>
        """
        ));
    }

    public override async Task TicketReceived(TicketReceivedContext context)
    {
        await base.TicketReceived(context);

        if(context.Result.Succeeded)
        {
            var identity = context.Principal.Identities.First();
            identity.AddClaim(new("issuer", context.Properties.Items["issuer"] ?? string.Empty));
        }
    }
}

internal static class XmlElementExtensions
{
    public static void AddAuthnMethod(this XmlNode parent, string methodName, bool enabled)
    {
        var doc = parent.OwnerDocument ?? throw new InvalidOperationException("Parent node must have an owner document.");
        var methodElement = doc.CreateElement("akdb", methodName, "https://www.akdb.de/request/2018/09");
        var enabledElement = doc.CreateElement("akdb", "Enabled", "https://www.akdb.de/request/2018/09");
        enabledElement.InnerText = enabled.ToString().ToLower();
        methodElement.AppendChild(enabledElement);
        parent.AppendChild(methodElement);
    }

    public static void AddAttribute(this XmlNode parent, string attributeName, bool required)
    {
        var doc = parent.OwnerDocument ?? throw new InvalidOperationException("Parent node must have an owner document.");
        var attributeElement = doc.CreateElement("akdb", "RequestedAttribute", "https://www.akdb.de/request/2018/09");
        attributeElement.SetAttribute("Name", attributeName);
        attributeElement.SetAttribute("RequiredAttribute", required.ToString().ToLower());
        parent.AppendChild(attributeElement);
    }
}
