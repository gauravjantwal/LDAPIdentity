using System.DirectoryServices;

namespace LDAPIdentity.Extensions.DirectoryEntryExtension
{
    /// <summary>
    /// Collection of extension methods for <see cref="DirectoryEntry"/>
    /// </summary>
    static class DirectoryEntryExtensionMethods
    {
        /// <summary>
        /// Gets the associated <paramref name="property"/> from the user's directory entry.
        /// </summary>
        /// <param name="directoryEntry">The current instance of user's LDAP entry.</param>
        /// <param name="property">The property to be fetched from the user's <paramref name="directoryEntry"/> object.</param>
        /// <returns>Value of the property, if any.</returns>
        public static string GetPropertyValue(this DirectoryEntry directoryEntry, string property)
        {
            if (directoryEntry == null || property == null)
            {
                return default;
            }
            return directoryEntry.Properties.Contains(property) ? directoryEntry.Properties[property]?.Value?.ToString() : null;
        }
        /// <summary>
        /// Sets the <paramref name="value"/> of the user's directory entry's <paramref name="property"/>.
        /// </summary>
        /// <param name="directoryEntry">The current instance of user's LDAP entry.</param>
        /// <param name="property">The property to set in the user's <paramref name="directoryEntry"/> object.</param>
        /// <param name="value">The value of the <paramref name="property"/> to set in user's <paramref name="directoryEntry"/> object.</param>
        /// <returns>The input <paramref name="directoryEntry"/> object with value set.</returns>
        public static DirectoryEntry SetPropertyValue(this DirectoryEntry directoryEntry, string property, string value)
        {
            if (directoryEntry == null || property == null)
            {
                return directoryEntry;
            }
            if (string.IsNullOrWhiteSpace(value))
            {
                value = null;
            }
            if (directoryEntry.Properties.Contains(property))
            {
                directoryEntry.Properties[property].Value = value;
            }
            else
            {
                directoryEntry.Properties[property].Add(value);
            }
            return directoryEntry;
        }
    }
}