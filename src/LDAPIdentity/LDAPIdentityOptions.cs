using System;
using System.Collections.Generic;
using System.Text;

namespace LDAPIdentity
{
    /// <summary>
    /// Represents options that configure LDAP authentication.
    /// </summary>
    public class LDAPIdentityOptions
    {
        /// <summary>
        /// Identifies the configuration section requried for LDAP settings.
        /// </summary>
        public const string LDAPOptionsKey = "LDAPIdentity";
        /// <summary>
        /// Identifies whether to use LDAP.
        /// </summary>
        public bool SkipLDAP { get; set; } = false;
        /// <summary>
        /// Gets or sets the LDAP server host name.
        /// </summary>
        public string Hostname { get; set; }

        /// <summary>
        /// Gets or sets the TCP port on which the LDAP server is running. Defaults to 389.
        /// </summary>
        public int Port { get; set; } = 389;

        /// <summary>
        /// Gets or sets the domain name to use as distinguished name in conjuction with the username
        /// </summary>
        public string Domain { get; set; }
        /// <summary>
        /// Gets or sets the user's domain to be created, e.g. {0}@domain.com, {0}@domain.net so user's UserPrincipalName may be created.
        /// </summary>
        public string UserDomain { get; set; }
        /// <summary>
        /// Gets or sets the domain/admin UserName to perform administrative tasks
        /// </summary>
        public string BindDn { get; set; }
        /// <summary>
        /// Gets or sets the domain/admin Password for <see cref="BindDn">DomainUser</seealso>
        /// </summary>
        public string BindCredentials { get; set; }
        /// <summary>
        /// Gets for sets the base CN & DN for search AD operation
        /// </summary>
        public string OUBase { get; set; }
        /// <summary>
        /// Gets for sets the filter for filtering results from AD
        /// </summary>
        public string Filter { get; set; }
    }
}
