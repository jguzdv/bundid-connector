namespace JGUZDV.BundId.SAMLProxy.SAML2
{
    public static class BundIdAttributes
    {
        /// <summary>
        /// Gender of the person as defined by ISO 5281:2004.
        /// </summary>
        public const string Gender = "urn:oid:1.3.6.1.4.1.33592.1.3.5";

        /// <summary>
        /// Academic title of the person.
        /// </summary>
        public const string PersonalTitle = "urn:oid:0.9.2342.19200300.100.1.40";

        public const string GivenName = "urn:oid:2.5.4.42";
        public const string Surname = "urn:oid:2.5.4.4";
        public const string Birthdate = "urn:oid:1.2.40.0.10.2.1.1.55";
        public const string BirthName = "urn:oid:1.2.40.0.10.2.1.1.225566"; 
        public const string PlaceOfBirth = "urn:oid:1.3.6.1.5.5.7.9.2";
        
        public const string PostalCode = "urn:oid:2.5.4.17";
        public const string LocalityName = "urn:oid:2.5.4.7";
        public const string PostalAddress = "urn:oid:2.5.4.16";
        /// <summary>
        /// Country of residence(?) represented as ISO 3166-1 alpha-2 code.
        /// </summary>
        public const string Country = "urn:oid:1.2.40.0.10.2.1.1.225599";

        /// <summary>
        /// Nationality of the person represented as ICAO code.
        /// </summary>
        public const string Nationality = "urn:oid:1.2.40.0.10.2.1.1.225577";
        
        public const string Mail = "urn:oid:0.9.2342.19200300.100.1.3";
        
        /// <summary>
        /// TODO: Needs documentaton
        /// </summary>
        public const string EIDCitizenQaaLevel = "urn:oid:1.2.40.0.10.2.1.1.261.94";

        /// <summary>
        /// bereichsspezifisches Personenkennzeiten
        /// </summary>
        public const string BPK = "urn:oid:1.2.40.0.10.2.1.1.149"; // bPK

        /// <summary>
        /// 'bereichsspezifisches Personenkennzeichen 2'
        /// </summary>
        public const string BPK2 = "urn:oid:1.3.6.1.4.1.25484.494450.3"; // bPK2

        /// <summary>
        /// TODO
        /// </summary>
        public const string LegacyPostkorbHandle = "urn:oid:2.5.4.18"; // legacyPostkorbHandle
    }
}
