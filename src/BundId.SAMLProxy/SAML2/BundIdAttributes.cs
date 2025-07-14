namespace JGUZDV.BundId.SAMLProxy.SAML2
{
    public static class BundIdAttributes
    {
        /// <summary>
        /// Gender of the person as defined by ISO 5281:2004.
        /// </summary>
        public const string Gender = "1.3.6.1.4.1.33592.1.3.5";

        /// <summary>
        /// Academic title of the person.
        /// </summary>
        public const string PersonalTitle = "0.9.2342.19200300.100.1.40";

        public const string GivenName = "2.5.4.42";
        public const string Surname = "2.5.4.4";
        public const string Birthdate = "1.2.40.0.10.2.1.1.55";
        public const string BirthName = "1.2.40.0.10.2.1.1.225566"; 
        public const string PlaceOfBirth = "1.3.6.1.5.5.7.9.2";
        
        public const string PostalCode = "2.5.4.17";
        public const string LocalityName = "2.5.4.7";
        public const string PostalAddress = "2.5.4.16";

        /// <summary>
        /// Country of residence(?) represented as ISO 3166-1 alpha-2 code.
        /// </summary>
        public const string Country = "1.2.40.0.10.2.1.1.225599";

        /// <summary>
        /// Nationality of the person represented as ICAO code.
        /// </summary>
        public const string Nationality = "1.2.40.0.10.2.1.1.225577";
        
        public const string Mail = "0.9.2342.19200300.100.1.3";
        
        /// <summary>
        /// TODO: Needs documentaton
        /// </summary>
        public const string EIDCitizenQaaLevel = "1.2.40.0.10.2.1.1.261.94";

        /// <summary>
        /// TODO
        /// </summary>
        public const string BPK = "1.2.40.0.10.2.1.1.149"; // bPK

        /// <summary>
        /// TODO
        /// </summary>
        public const string BPK2 = "1.3.6.1.4.1.25484.494450.3"; // bPK2

        /// <summary>
        /// TODO
        /// </summary>
        public const string LegacyPostkorbHandle = "2.5.4.18"; // legacyPostkorbHandle
    }
}
