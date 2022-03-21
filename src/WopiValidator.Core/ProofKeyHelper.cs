// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Microsoft.Office.WopiValidator.Core
{
	public class ProofKeyInput
	{
		public string AccessToken { get; private set; }
		public long Timestamp { get; private set; }
		public string Url { get; private set; }

		public ProofKeyInput(string accessToken, long timestamp, string url)
		{
			AccessToken = accessToken;
			Timestamp = timestamp;
			Url = url;
		}
	}

	public class ProofKeyOutput
	{
		public string AccessToken { get; private set; }
		public byte[] AccessTokenBytes;
		public int AccessTokenLength { get; private set; }
		public byte[] AccessTokenLengthBytes;

		public string Url { get; private set; }
		public byte[] UrlBytes;
		public int UrlLength { get; private set; }
		public byte[] UrlLengthBytes;

		public long TimeStamp { get; private set; }
		public byte[] TimeStampBytes;
		public int TimeStampLength { get; private set; }
		public byte[] TimeStampLengthBytes;

		public int PreSigningLength { get; private set; }
		public byte[] PreSigningBytes;

		public string SignedBase64ProofKey { get; set; }

		public ProofKeyOutput(
			string accessToken,
			byte[] accessTokenBytes,
			int accessTokenLength,
			byte[] accessTokenLengthBytes,
			string url,
			byte[] urlBytes,
			int urlLength,
			byte[] urlLengthBytes,
			long timestamp,
			byte[] timestampBytes,
			int timestampLength,
			byte[] timestampLengthBytes,
			byte[] preSigningBytes)
		{
			AccessToken = accessToken;
			AccessTokenBytes = accessTokenBytes;
			AccessTokenLength = accessTokenLength;
			AccessTokenLengthBytes = accessTokenLengthBytes;
			Url = url;
			UrlBytes = urlBytes;
			UrlLength = urlLength;
			UrlLengthBytes = urlLengthBytes;
			TimeStamp = timestamp;
			TimeStampBytes = timestampBytes;
			TimeStampLength = timestampLength;
			TimeStampLengthBytes = timestampLengthBytes;
			PreSigningLength = preSigningBytes.Length;
			PreSigningBytes = preSigningBytes;
		}
	}

	public class ProofKeysHelper
	{
		public static void GenerateProofKeys(string filePath, int keySize = 2048)
		{
			var proofRsaAlg = new RSACryptoServiceProvider(keySize);
			var oldProofRsaAlg = new RSACryptoServiceProvider(keySize);
			string proofKeys = proofRsaAlg.ToXmlString(true);
			string oldProofKeys = oldProofRsaAlg.ToXmlString(true);

			Console.WriteLine("Proof Public Key");
			Console.WriteLine(Convert.ToBase64String(proofRsaAlg.ExportCspBlob(false)));
			Console.WriteLine("Old Proof Public Key");
			Console.WriteLine(Convert.ToBase64String(oldProofRsaAlg.ExportCspBlob(false)));

			var writer = XmlWriter.Create(filePath);
			writer.WriteStartDocument();
			writer.WriteStartElement("keys");
			writer.WriteStartElement("new");
			writer.WriteRaw(proofKeys);
			writer.WriteEndElement();
			writer.WriteStartElement("old");
			writer.WriteRaw(oldProofKeys);
			writer.WriteEndElement();
			writer.WriteEndElement();
			writer.WriteEndDocument();
			writer.Close();
		}

		public static (RSACryptoServiceProvider current, RSACryptoServiceProvider old) ImportProofKeys(string filePath)
		{
			var reader = XmlReader.Create(filePath);
			string proofKeys = string.Empty, oldProofKeys = string.Empty;
			while (reader.Read())
			{
				if (reader.NodeType == XmlNodeType.Element && reader.Name.Equals("new"))
				{
					proofKeys = reader.ReadOuterXml();
				}
				if (reader.NodeType == XmlNodeType.Element && reader.Name.Equals("old"))
				{
					oldProofKeys = reader.ReadOuterXml();
				}
			}

			if (proofKeys.Length == 0 || oldProofKeys.Length == 0)
			{
				throw new ArgumentException("Could not load proof keys.");
			}

			var proofRsaAlg = new RSACryptoServiceProvider();
			proofRsaAlg.FromXmlString(proofKeys);
			var oldProofRsaAlg = new RSACryptoServiceProvider();
			oldProofRsaAlg.FromXmlString(oldProofKeys);

			return (proofRsaAlg, oldProofRsaAlg);
		}

		public static ProofKeyOutput GetSignedProofData(ProofKeyInput proofData, RSACryptoServiceProvider rsaAlg)
		{
			ProofKeyOutput output = GetProofData(proofData);

			using (SHA256CryptoServiceProvider hashAlg = new SHA256CryptoServiceProvider())
			{
				byte[] signedProofBytes = rsaAlg.SignData(output.PreSigningBytes, hashAlg);
				output.SignedBase64ProofKey = Convert.ToBase64String(signedProofBytes);

				return output;
			}
		}

		private static ProofKeyOutput GetProofData(ProofKeyInput proofData)
		{
			if (proofData.AccessToken == null) {
				throw new ProofKeySigningException(nameof(proofData.AccessToken));
			}

			// Get the final values we'll operate on
			string accessToken = proofData.AccessToken;
			string hostUrl = proofData.Url.ToUpperInvariant();
			long timeStamp = proofData.Timestamp;

			// Encode values from headers into byte[]
			byte[] accessTokenBytes = Encoding.UTF8.GetBytes(accessToken);
			byte[] hostUrlBytes = Encoding.UTF8.GetBytes(hostUrl);
			byte[] timeStampBytes = EncodeNumber(timeStamp);

			int accessTokenLength = accessTokenBytes.Length;
			int hostUrlLength = hostUrlBytes.Length;
			int timeStampLength = timeStampBytes.Length;

			byte[] accessTokenLengthBytes = EncodeNumber(accessTokenLength);
			byte[] hostUrlLengthBytes = EncodeNumber(hostUrlLength);
			byte[] timeStampLengthBytes = EncodeNumber(timeStampLength);

			// prepare a list that will be used to combine all those arrays together
			List<byte> expectedProof = new List<byte>(
				accessTokenLengthBytes.Length + accessTokenLength +
				hostUrlLengthBytes.Length + hostUrlLength +
				timeStampLengthBytes.Length + timeStampLength);

			expectedProof.AddRange(accessTokenLengthBytes);
			expectedProof.AddRange(accessTokenBytes);
			expectedProof.AddRange(hostUrlLengthBytes);
			expectedProof.AddRange(hostUrlBytes);
			expectedProof.AddRange(timeStampLengthBytes);
			expectedProof.AddRange(timeStampBytes);

			// create another byte[] from that list
			byte[] preSigningBytes = expectedProof.ToArray();

			return new ProofKeyOutput(
				accessToken,
				accessTokenBytes,
				accessTokenLength,
				accessTokenLengthBytes,
				hostUrl,
				hostUrlBytes,
				hostUrlLength,
				hostUrlLengthBytes,
				timeStamp,
				timeStampBytes,
				timeStampLength,
				timeStampLengthBytes,
				preSigningBytes);
		}

		private static byte[] EncodeNumber(int value)
		{
			return BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(value));
		}

		private static byte[] EncodeNumber(long value)
		{
			return BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(value));
		}
	}

	public class ProofKeySigningException : ArgumentNullException
	{
		public ProofKeySigningException()
			: base()
		{
		}

		public ProofKeySigningException(string paramName)
			: base(paramName)
		{
		}
	}
}
