using IdentityModel;
using LDAPIdentity.Extensions.DirectoryEntryExtension;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;

namespace LDAPIdentity.Extensions.UserPrincipalExtension
{
    /// <summary>
    /// Collection of extension methods for <see cref="UserPrincipal"/> and <see cref="PrincipalContext"/>.
    /// </summary>
    static class UserPrincipalExtensionMethods
    {
        /// <summary>
        /// Adds the specified <paramref name="claims"/> to the <paramref name="userPrincipal"/> in the LDAP store.
        /// </summary>
        /// <param name="userPrincipal">The LDAP user principle of type <see cref="UserPrincipal"/>.</param>
        /// <param name="claims">Collection of <see cref="Claim"/> to add for the <paramref name="userPrincipal"/>.</param>
        public static void AddClaims(this UserPrincipal userPrincipal, IEnumerable<Claim> claims)
        {
            if (userPrincipal == null || claims == null || claims.Count() == 0)
            {
                return;
            }
            userPrincipal
                .SetExpressionValue((u, value) => u.GivenName = value, claims.FirstOrDefault(c => c.Type == JwtClaimTypes.GivenName))
                .SetExpressionValue((u, value) => u.Surname = value, claims.FirstOrDefault(c => c.Type == JwtClaimTypes.FamilyName))
                .SetExpressionValue((u, value) => u.DisplayName = value, claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Name));
            var _directoryEntry = userPrincipal.GetDirectoryEntry();
            foreach (var claim in claims.GetCustomClaims())
            {
                _directoryEntry.SetPropertyValue(claim.Type, claim.Value);
            }
        }
        /// <summary>
        /// Initializes new <see cref="UserPrincipal"/> using <paramref name="principalContext"/> for <paramref name="user"/>.
        /// </summary>
        /// <typeparam name="TUser">The type of <paramref name="user"/> to fetch details from.</typeparam>
        /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
        /// <param name="principalContext">The LDAP context where the user will be created.</param>
        /// <param name="user">The user to get details from.</param>
        /// <param name="userDomain">The domain name part of the user's UserPrincipalName.</param>
        /// <returns>Instance of <see cref="UserPrincipal"/> with all required information.</returns>
        public static UserPrincipal CreateUserPrincipal<TUser, TKey>(this PrincipalContext principalContext, TUser user, string userDomain)
            where TUser : IdentityUser<TKey>
            where TKey : IEquatable<TKey>
        {
            if (principalContext == null || user == null)
            {
                return default;
            }
            if (user.UserName == null || user.Email == null)
            {
                return default;
            }
            return new UserPrincipal(principalContext)
            {
                PasswordNeverExpires = true,
                PasswordNotRequired = false,
                Enabled = true,
                Name = user.UserName,
                SamAccountName = user.UserName,
                UserPrincipalName = string.Format(userDomain, user.UserName),
                EmailAddress = user.Email
            };
        }
        /// <summary>
        /// Sets LDAP's <paramref name="userPrincipal"/> Name, EmailAddress, SamAccountName and UserPrincipalName using <paramref name="userEmail"/> and <paramref name="userDomain"/>.
        /// </summary>
        /// <param name="userPrincipal">The LDAP <see cref="UserPrincipal"/> fot the user.</param>
        /// <param name="userEmail">The user's email address.</param>
        /// <param name="userDomain">The domain name part of the user's UserPrincipalName.</param>
        public static void ChangeEmail(this UserPrincipal userPrincipal, string userEmail, string userDomain)
        {
            if (userPrincipal == null || userEmail == null || userDomain == null)
            {
                return;
            }
            var _username = userEmail.GetUserName();
            if (_username == null)
            {
                return;
            }
            var _entry = userPrincipal.GetDirectoryEntry();
            _entry.Properties["mail"].Value = userEmail;
            _entry.Properties["userPrincipalName"].Value = string.Format(userDomain, _username);
            _entry.Properties["sAMAccountName"].Value = _username;
            _entry.CommitChanges();
            _entry.Rename($"CN={_username}");
        }
        /// <summary>
        /// Initializes a new <typeparamref name="TUser"/> instance with values from LDAP's <paramref name="userPrincipal"/>.
        /// </summary>
        /// <typeparam name="TUser">The type of user to instintiate using <paramref name="userPrincipal"/>.</typeparam>
        /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
        /// <param name="userPrincipal">The LDAP <see cref="UserPrincipal"/> of the user.</param>
        /// <returns>The instianted <typeparamref name="TUser"/> with values set.</returns>
        public static TUser CreateUser<TUser, TKey>(this UserPrincipal userPrincipal)
            where TUser : IdentityUser<TKey>
            where TKey : IEquatable<TKey>
        {
            if (userPrincipal == null)
            {
                return default;
            }
            var _user = Activator.CreateInstance<TUser>();
            _user.UserName = userPrincipal.EmailAddress;
            _user.Email = userPrincipal.EmailAddress;
            _user.PhoneNumber = userPrincipal.VoiceTelephoneNumber;
            return _user;
        }
        /// <summary>
        /// Gets a list of <see cref="Claim"/>s belonging to the specified <paramref name="userPrincipal"/>.
        /// </summary>
        /// <param name="userPrincipal">The LDAP <see cref="UserPrincipal"/> of the user.</param>
        /// <returns>Collection of <see cref="Claim"/> for the <paramref name="userPrincipal"/>.</returns>
        public static IEnumerable<Claim> GetClaims(this UserPrincipal userPrincipal)
        {
            if (userPrincipal == null)
            {
                yield break;
            }
            if (!string.IsNullOrWhiteSpace(userPrincipal.GivenName))
            {
                yield return new Claim(JwtClaimTypes.GivenName, userPrincipal.GivenName);
            }
            if (!string.IsNullOrWhiteSpace(userPrincipal.Surname))
            {
                yield return new Claim(JwtClaimTypes.FamilyName, userPrincipal.Surname);
            }
            if (!string.IsNullOrWhiteSpace(userPrincipal.Name))
            {
                yield return new Claim(JwtClaimTypes.Name, userPrincipal.DisplayName);
            }
            var _directoryEntry = userPrincipal.GetDirectoryEntry();
            foreach (var claimName in GetCustomClaims())
            {
                var _claimValue = _directoryEntry.GetPropertyValue(claimName);
                if (!string.IsNullOrWhiteSpace(_claimValue))
                {
                    yield return new Claim(claimName, _claimValue);
                }
            }
            yield break;
        }
        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="userPrincipal"/>.
        /// </summary>
        /// <param name="userPrincipal">The LDAP <see cref="UserPrincipal"/> of the user.</param>
        /// <param name="claims">The collection of <see cref="Claim"/> to remove.</param>
        public static void RemoveClaims(this UserPrincipal userPrincipal, IEnumerable<Claim> claims)
        {
            if (userPrincipal == null || claims == null || claims.Count() == 0)
            {
                return;
            }
            userPrincipal.AddClaims(claims.Select(c => new Claim(c.Type, string.Empty)));
        }
        /// <summary>
        /// Sets <paramref name="claim"/> value to the instance <typeparamref name="T"/>, using <paramref name="action"/>.
        /// </summary>
        /// <typeparam name="T">Type of the <paramref name="typeInstance"/> to set the claim value for.</typeparam>
        /// <param name="typeInstance">Instance of <typeparamref name="T"/> to set the claim value.</param>
        /// <param name="action">Function to select property of <typeparamref name="T"/> to set the claim value for.</param>
        /// <param name="claim">The claim to set to the <paramref name="typeInstance"/>.</param>
        /// <returns>The input instance of <typeparamref name="T"/></returns>
        static T SetExpressionValue<T>(this T typeInstance, Action<T, string> action, Claim claim)
        {
            if (claim == null)
            {
                return typeInstance;
            }
            action.Invoke(typeInstance, string.IsNullOrWhiteSpace(claim.Value) ? null : claim.Value);
            return typeInstance;
        }
        /// <summary>
        /// Parses <see cref="DirectoryEntry"/> instance from <paramref name="userPrincipal"/> instance.
        /// </summary>
        /// <param name="userPrincipal">The LDAP <see cref="UserPrincipal"/> of the user.</param>
        /// <returns></returns>
        static DirectoryEntry GetDirectoryEntry(this UserPrincipal userPrincipal)
        {
            if (userPrincipal == null)
            {
                return default;
            }
            return userPrincipal.GetUnderlyingObject() as DirectoryEntry;
        }
        /// <summary>
        /// Filters the custom claims from the input <paramref name="claims"/>.
        /// </summary>
        /// <param name="claims">Collection of user <see cref="Claim"/>.</param>
        /// <returns>Filtered collection of user's custom <see cref="Claim"/>.</returns>
        static IEnumerable<Claim> GetCustomClaims(this IEnumerable<Claim> claims)
        {
            if (claims == null || claims.Count() == 0)
            {
                return default;
            }
            var _properties = GetCustomClaims().Except(GetExcludedClaims());
            return claims.Where(c => _properties.Contains(c.Type));
        }
        /// <summary>
        /// Gets configured custom claims for the user in LDAP.
        /// </summary>
        /// <returns>Collection of <see cref="string"/> claims.</returns>
        static IEnumerable<string> GetCustomClaims()
        {
            yield break;
        }
        /// <summary>
        /// List of excluded claims, not handled by LDAP.
        /// </summary>
        /// <returns>Collection of <see cref="string"/> claims.</returns>
        static IEnumerable<string> GetExcludedClaims()
        {
            yield break;
        }
        /// <summary>
        /// Parses and fetches the username from <paramref name="email"/> address.
        /// </summary>
        /// <param name="email">Email <see cref="string"/>.</param>
        /// <returns>User's username from input user object.</returns>
        public static string GetUserName(this string email)
        {
            if (email == null)
            {
                return default;
            }
            if (email.Contains("@"))
            {
                return email.Split('@')[0];
            }
            return email;
        }
    }
}