using LDAPIdentity.Core;
using LDAPIdentity.Interfaces;
using LDAPIdentity.Servicess;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Diagnostics.CodeAnalysis;

namespace LDAPIdentity
{
    /// <summary>
    /// Extension methods for <see cref="IdentityBuilder"/> to configure the Hybrid (LDAP + EF), Identity User's Operation.
    /// </summary>
    public static class LDAPIdentityBuilderExtension
    {
        /// <summary>
        /// Adds LDAP + EF Hybrid UserStore and UserManager to Identity. Configures <see cref="LDAPIdentityOptions"/> for the given service collection.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> being used to configure the context.</param>
        /// <param name="options">An optional action to allow LDAP specific configuration.</param>
        /// <returns>The input <see cref="IdentityBuilder"/>, so that further configuration can be chained.</returns>
        public static IdentityBuilder AddLDAPIdentity<TUser, TDbContext>(this IdentityBuilder builder, [NotNull] Func<LDAPIdentityOptions> options)
            where TUser : IdentityUser<string>, new()
            where TDbContext : DbContext
        {
            return builder.AddLDAPIdentity<TUser, TDbContext, string>(options);
        }
        /// <summary>
        /// Adds LDAP + EF Hybrid UserStore and UserManager to Identity. Configures <see cref="LDAPIdentityOptions"/> for the given service collection.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> being used to configure the context.</param>
        /// <param name="options">An optional action to allow LDAP specific configuration.</param>
        /// <returns>The input <see cref="IdentityBuilder"/>, so that further configuration can be chained.</returns>
        public static IdentityBuilder AddLDAPIdentity<TUser, TDbContext, TKey>(this IdentityBuilder builder, [NotNull] Func<LDAPIdentityOptions> options)
            where TUser : IdentityUser<TKey>, new()
            where TKey : IEquatable<TKey>
            where TDbContext : DbContext
        {
            var _options = options.Invoke();
            if (_options.SkipLDAP)
            {
                return builder;
            }
            var _services = builder.Services;
            _services
                .Configure<LDAPIdentityOptions>(o =>
                {
                    var _options = options.Invoke();
                    o.BindCredentials = _options.BindCredentials;
                    o.BindDn = _options.BindDn;
                    o.Domain = _options.Domain;
                    o.Filter = _options.Filter;
                    o.Hostname = _options.Hostname;
                    o.OUBase = _options.OUBase;
                    o.Port = _options.Port;
                    o.UserDomain = _options.UserDomain;
                })
                .TryAddScoped<ILDAPService<TUser, TKey>, LDAPService<TUser, TKey>>();
            _services
                .TryAddScoped<DbContext, TDbContext>();
            return builder
                .AddUserStore<UserStore<TUser, TKey>>()
                .AddUserManager<UserManager<TUser, TKey>>();
        }
    }
}