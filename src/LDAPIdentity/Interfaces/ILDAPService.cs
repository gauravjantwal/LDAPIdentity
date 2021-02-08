using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace LDAPIdentity.Interfaces
{
    /// <summary>
    /// Provides API to access user LDAP operations.
    /// </summary>
    /// <typeparam name="TUser">Type of user to operate LDAP actions.</typeparam>
    /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
    public interface ILDAPService<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Adds the specified <paramref name="claims"/> to the <paramref name="user"/> in the LDAP store, as an asynchronous operation.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> to add the claim to.</param>
        /// <param name="claims">The collection of <see cref="Claim"/> to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default);
        /// <summary>
        /// Updates a users <paramref name="email"/> and username for the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be updated.</param>
        /// <param name="newEmail">The new email address.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task ChangeEmailAsync(TUser user, string newEmail, CancellationToken cancellationToken = default);
        /// <summary>
        /// Creates the specified <paramref name="user"/> in the LDAP store with given <paramref name="password"/>, as an asynchronous operation.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> to create.</param>
        /// <param name="password">The password for the user to store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task CreateAsync(TUser user, string password, CancellationToken cancellationToken = default);
        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the LDAP store, as an asynchronous operation.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task DeleteAsync(TUser user, CancellationToken cancellationToken = default);
        /// <summary>
        /// Finds and returns a <see cref="TUser"/>, if any, who has the specified <paramref name="userAttribute"/> and it's <paramref name="value"/>.
        /// </summary>
        /// <param name="userAttribute">The <see cref="IdentityType"/> to search with.</param>
        /// <param name="value">Value of the <see cref="IdentityType"/> to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="TUser"/> matching the specified <paramref name="value"/>, if it exists.</returns>
        Task<TUser> FindByAttributeAsync(IdentityType identityType, string value, CancellationToken cancellationToken = default);
        /// <summary>
        /// Gets a list of <see cref="Claim"/>s belonging to the specified <paramref name="user"/>, as an asynchronous operation.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> whose claims to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.</returns>
        Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default);
        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">The collection of <see cref="Claim"/> to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default);
        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> to replace the claim on.</param>
        /// <param name="claim">The <see cref="Claim"/> to replace.</param>
        /// <param name="claim">The new <see cref="Claim"/> to replace the existing <paramref name="claim"/> with.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default);
        /// <summary>
        /// Sets the phone number for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> whose phone number to set.</param>
        /// <param name="phoneNumber">The phone number to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default);
        /// <summary>
        /// Updates a user's password in LDAP.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> whose password is to be updated.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task UpdatePasswordAsync(TUser user, string newPassword, CancellationToken cancellationToken = default);
        /// <summary>
        /// Returns a <see cref="bool"/> indicating the result of a password comparison in LDAP.
        /// </summary>
        /// <param name="user">The <see cref="TUser"/> whose password should be verified.</param>
        /// <param name="password">The password to verify.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task<bool> VerifyPasswordAsync(TUser user, string password, CancellationToken cancellationToken = default);
    }
}