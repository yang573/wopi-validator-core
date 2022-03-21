﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using CommandLine;
using Microsoft.Office.WopiValidator.Core;

namespace Microsoft.Office.WopiValidator
{
	/// <summary>
	/// Represents set of command line arguments that can be used to modify behavior of the application.
	/// </summary>
	class Options
	{
		[Option('k', "generate_keys", Required = false, HelpText = "Generate proof key pairs. Ignores all other arguments and skips running tests.")]
		public bool GenerateKeys { get; set; }

		[Option('w', "wopisrc", Required = false, HelpText = "Required. WopiSrc URL for a wopitest file")]
		public string WopiEndpoint { get; set; }

		[Option('t', "token", Required = false, HelpText = "Required. WOPI access token")]
		public string AccessToken { get; set; }

		[Option('l', "token_ttl", Required = false, Default = -1, HelpText = "Required. WOPI access token ttl. Must be 0 or greater.")]
		public long AccessTokenTtl { get; set; }

		[Option('c', "config", Required = false, Default = "TestCases.xml", HelpText = "Path to XML file with test definitions")]
		public string RunConfigurationFilePath { get; set; }

		[Option('g', "testgroup", Required = false, HelpText = "Run only the tests in the specified group (cannot be used with testname)")]
		public string TestGroup { get; set; }

		[Option('n', "testname", Required = false, HelpText = "Run only the test specified (cannot be used with testgroup)")]
		public string TestName { get; set; }

		[Option('e', "testcategory", Required = false, Default = TestCategory.All, HelpText = "Run only the tests in the specified category")]
		public TestCategory TestCategory { get; set; }

		[Option('s', "ignore-skipped", Required = false, HelpText = "Don't output any info about skipped tests.")]
		public bool IgnoreSkipped { get; set; }
	}
}
