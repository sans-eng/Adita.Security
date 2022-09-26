using Adita.Security.Principal;
using Adita.Security.Claims;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Adita.Security.Authorization;

namespace Adita.Security.Test.Authorization
{
    [TestClass]
    public class AuthorizaztionManagerTest
    {
        [Authorize("admin")]
        public int Resource1 { get; }
        [Authorize("user")]
        public int Resource2 { get; }

        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            ApplicationIdentity applicationIdentity = new(new List<Claim> { new Claim(ClaimTypes.Name, "Adi"), new Claim(ClaimTypes.Role, "admin") }, "password");

            ApplicationPrincipal applicationPrincipal = new(applicationIdentity);

            AppDomain.CurrentDomain.SetThreadPrincipal(applicationPrincipal);
        }

        [TestMethod]
        [Authorize("admin")]
        public void CanAcceptPermission()
        {
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.CheckPermission());
        }

        [TestMethod]
        [Authorize("user")]
        public void CanRefusePermission()
        {
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.CheckPermission());
        }

        [TestMethod]
        public void CanAcceptResourcePermission()
        {
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.HasPermission<AuthorizaztionManagerTest>(nameof(Resource1)));
        }

        [TestMethod]
        public void CanRefuseResourcePermission()
        {
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.HasPermission<AuthorizaztionManagerTest>(nameof(Resource2)));
        }

        [TestMethod]
        public void CanAcceptRole()
        {
            AuthorizationManager authorizationManager = new();
            Assert.IsTrue(authorizationManager.IsInRole("admin"));
        }
        [TestMethod]
        public void CanRefuseRole()
        {
            AuthorizationManager authorizationManager = new();
            Assert.IsFalse(authorizationManager.IsInRole("user"));
        }
    }
}
