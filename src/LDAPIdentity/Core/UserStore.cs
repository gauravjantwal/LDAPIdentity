using LDAPIdentity.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace LDAPIdentity.Core
{
    /// <summary>
    /// Represents a new instance of a persistence store for users, using the default implementation of <see cref="Microsoft.AspNetCore.Identity.IdentityUser"/>.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
    public class UserStore<TUser, TKey> : UserStore<TUser, IdentityRole<TKey>, DbContext, TKey>
       where TUser : IdentityUser<TKey>, new()
       where TKey : IEquatable<TKey>
    {
        private readonly ILDAPService<TUser, TKey> _iLDAPServices;
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore"/>.
        /// </summary>
        /// <param name="context">The <see cref="DbContext"/>.</param>
        /// <param name="iLDAPServices">The <see cref="ILDAPUserServices<TUser>"/></param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserStore(DbContext context, ILDAPService<TUser, TKey> iLDAPServices, IdentityErrorDescriber describer = null)
            : base(context, describer)
            => _iLDAPServices = iLDAPServices;
        /// <summary>
        /// Deletes the specified user from LDAP and the default user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            await _iLDAPServices.DeleteAsync(user, cancellationToken);
            return await base.DeleteAsync(user, cancellationToken);
        }
        /// <summary>
        /// Returns a flag indicating if the specified user has a password, which is hard-coded to be always true for LDAP
        /// </summary>
        /// <param name="user"> The user to retrieve the password hash for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task"/> containing a flag indicating if the specified user has a password. If the user has a password the returned value with be true, otherwise it will be false.</returns>
        public override Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default)
        {
            //return base.HasPasswordAsync(user, cancellationToken);
            return Task.FromResult(true);
        }
    }
}