// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using NJsonSchema;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Microsoft.Office.WopiValidator.Core.ResourceManagement
{
	internal class JsonSchemas
	{
		private const string SchemasPath = "Microsoft.Office.WopiValidator.Core.JsonSchemas.";
		private const string SchemaSuffix = ".json";

		public static IDictionary<string, JsonSchema> Schemas { get; }

		static JsonSchemas()
		{
			Schemas = LoadAllSchemasAsync().GetAwaiter().GetResult();
		}

		private static async Task<IDictionary<string, JsonSchema>> LoadAllSchemasAsync()
		{
			var schemaIds = Assembly.GetExecutingAssembly().GetManifestResourceNames()
				.Where(name => name.StartsWith(SchemasPath))
				.Select(name => ParseSchemaIdFromEmbeddedResourceName(name));
			var schemaTasks = schemaIds.Select(async x => await LoadJsonSchemaAsync(x));
			var schemas = await Task.WhenAll(schemaTasks);
			return schemaIds.Zip(schemas, (k, v) => new { k, v })
				.ToDictionary(x => x.k, x => x.v);
		}

		private static string ParseSchemaIdFromEmbeddedResourceName(string resourceName)
		{
			if (!resourceName.StartsWith(SchemasPath))
			{
				return null;
			}

			int startIndex = SchemasPath.Length;
			int length = resourceName.Length - SchemasPath.Length - SchemaSuffix.Length;
			return resourceName.Substring(startIndex, length);
		}

		private static async Task<JsonSchema> LoadJsonSchemaAsync(string schemaId)
		{
			string json = ReadFileFromAssembly(schemaId);
			return await JsonSchema.FromJsonAsync(json);
		}

		private static string ReadFileFromAssembly(string schemaId)
		{
			string json = null;
			string resourcePath = SchemasPath + schemaId + SchemaSuffix;

			Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourcePath);
			if (stream != null)
			{
				using (StreamReader streamReader = new StreamReader(stream))
				{
					json = streamReader.ReadToEnd();
				}
			}
			return json;
		}
	}
}
