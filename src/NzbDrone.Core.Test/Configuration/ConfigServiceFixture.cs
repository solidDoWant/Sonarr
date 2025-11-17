using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using Moq;
using NUnit.Framework;
using NzbDrone.Core.Configuration;
using NzbDrone.Test.Common;

namespace NzbDrone.Core.Test.Configuration
{
    [TestFixture]
    public class ConfigServiceFixture : TestBase<ConfigService>
    {
        [SetUp]
        public void SetUp()
        {
        }

        [Test]
        public void Add_new_value_to_database()
        {
            const string key = "RssSyncInterval";
            const int value = 12;

            Subject.RssSyncInterval = value;

            AssertUpsert(key, value);
        }

        [Test]
        public void Get_value_should_return_default_when_no_value()
        {
            Subject.RssSyncInterval.Should().Be(15);
        }

        [Test]
        public void get_value_with_persist_should_store_default_value()
        {
            var salt = Subject.HmacSalt;
            salt.Should().NotBeNullOrWhiteSpace();
            AssertUpsert("HmacSalt", salt);
        }

        [Test]
        public void get_value_with_out_persist_should_not_store_default_value()
        {
            var interval = Subject.RssSyncInterval;
            interval.Should().Be(15);
            Mocker.GetMock<IConfigRepository>().Verify(c => c.Insert(It.IsAny<Config>()), Times.Never());
        }

        private void AssertUpsert(string key, object value)
        {
            Mocker.GetMock<IConfigRepository>().Verify(c => c.Upsert(key.ToLowerInvariant(), value.ToString()));
        }

        [Test]
        [Description("This test will use reflection to ensure each config property read/writes to a unique key")]
        public void config_properties_should_write_and_read_using_same_key()
        {
            var configProvider = Subject;
            var allProperties = typeof(ConfigService).GetProperties().Where(p => p.GetSetMethod() != null).ToList();

            var keys = new List<string>();
            var values = new List<Config>();

            Mocker.GetMock<IConfigRepository>().Setup(c => c.Upsert(It.IsAny<string>(), It.IsAny<string>())).Callback<string, string>((key, value) =>
            {
                keys.Add(key);
                values.Add(new Config { Key = key, Value = value });
            });

            Mocker.GetMock<IConfigRepository>().Setup(c => c.All()).Returns(values);

            foreach (var propertyInfo in allProperties)
            {
                object value = null;

                if (propertyInfo.PropertyType == typeof(string))
                {
                    value = Guid.NewGuid().ToString();
                }
                else if (propertyInfo.PropertyType == typeof(int))
                {
                    value = DateTime.Now.Millisecond;
                }
                else if (propertyInfo.PropertyType == typeof(double))
                {
                    value = (double)DateTime.Now.Millisecond;
                }
                else if (propertyInfo.PropertyType == typeof(bool))
                {
                    value = true;
                }
                else if (propertyInfo.PropertyType.BaseType == typeof(Enum))
                {
                    value = 0;
                }

                propertyInfo.GetSetMethod().Invoke(configProvider, new[] { value });
                var returnValue = propertyInfo.GetGetMethod().Invoke(configProvider, null);

                if (propertyInfo.PropertyType.BaseType == typeof(Enum))
                {
                    returnValue = (int)returnValue;
                }

                returnValue.Should().Be(value, propertyInfo.Name);
            }

            keys.Should().OnlyHaveUniqueItems();
        }

        [Test]
        public void should_ignore_null_properties()
        {
            Mocker.GetMock<IConfigRepository>()
                  .Setup(v => v.Get("downloadedepisodesfolder"))
                  .Returns(new Config { Id = 1, Key = "DownloadedEpisodesFolder", Value = @"C:\test".AsOsAgnostic() });

            var dict = new Dictionary<string, object>();
            dict.Add("DownloadedEpisodesFolder", null);
            Subject.SaveConfigDictionary(dict);

            Mocker.GetMock<IConfigRepository>().Verify(c => c.Upsert("downloadedepisodesfolder", It.IsAny<string>()), Times.Never());
        }

        [Test]
        public void oidc_enabled_should_default_to_false()
        {
            Subject.OidcEnabled.Should().BeFalse();
        }

        [Test]
        public void oidc_enabled_can_be_set()
        {
            Subject.OidcEnabled = true;
            AssertUpsert("OidcEnabled", true);
        }

        [Test]
        public void oidc_authority_should_default_to_empty()
        {
            Subject.OidcAuthority.Should().Be(string.Empty);
        }

        [Test]
        public void oidc_authority_can_be_set()
        {
            const string authority = "https://auth.example.com";
            Subject.OidcAuthority = authority;
            AssertUpsert("OidcAuthority", authority);
        }

        [Test]
        public void oidc_client_id_can_be_set()
        {
            const string clientId = "sonarr-client";
            Subject.OidcClientId = clientId;
            AssertUpsert("OidcClientId", clientId);
        }

        [Test]
        public void oidc_client_secret_can_be_set()
        {
            const string clientSecret = "secret123";
            Subject.OidcClientSecret = clientSecret;
            AssertUpsert("OidcClientSecret", clientSecret);
        }

        [Test]
        public void oidc_scopes_should_default_to_openid_profile_email()
        {
            Subject.OidcScopes.Should().Be("openid profile email");
        }

        [Test]
        public void oidc_username_claim_should_default_to_preferred_username()
        {
            Subject.OidcUsernameClaim.Should().Be("preferred_username");
        }

        [Test]
        public void oidc_callback_path_should_default_to_auth_oidc_callback()
        {
            Subject.OidcCallbackPath.Should().Be("/auth/oidc/callback");
        }
    }
}
