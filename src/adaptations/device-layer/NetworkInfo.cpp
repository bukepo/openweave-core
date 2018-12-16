/*
 *
 *    Copyright (c) 2018 Nest Labs, Inc.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <Weave/DeviceLayer/internal/WeaveDeviceLayerInternal.h>
#include <Weave/DeviceLayer/internal/NetworkInfo.h>
#include <Weave/Core/WeaveTLV.h>
#include <Weave/Profiles/WeaveProfiles.h>

using namespace ::nl;
using namespace ::nl::Weave;
using namespace ::nl::Weave::TLV;
using namespace ::nl::Weave::Profiles::NetworkProvisioning;

using Profiles::kWeaveProfile_NetworkProvisioning;

namespace nl {
namespace Weave {
namespace DeviceLayer {
namespace Internal {

void NetworkInfo::Reset()
{
    NetworkType = kNetworkType_NotSpecified;
    NetworkId = 0;
    NetworkIdPresent = false;
    mWiFi.WiFiSSID[0] = 0;
    mWiFi.WiFiMode = kWiFiMode_NotSpecified;
    mWiFi.WiFiRole = kWiFiRole_NotSpecified;
    mWiFi.WiFiSecurityType = kWiFiSecurityType_NotSpecified;
    mWiFi.WiFiKeyLen = 0;
    mWiFi.WirelessSignalStrength = INT16_MIN;
    mThread.mIsExtendedPANIdSet = false;
}

WEAVE_ERROR NetworkInfo::Encode(nl::Weave::TLV::TLVWriter & writer) const
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    TLVType outerContainer;

    uint64_t tag = (writer.GetContainerType() == kTLVType_Array)
            ? AnonymousTag
            : ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_NetworkInformation);

    err = writer.StartContainer(tag, kTLVType_Structure, outerContainer);
    SuccessOrExit(err);

    if (NetworkIdPresent)
    {
        err = writer.Put(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_NetworkId), (uint32_t) NetworkId);
        SuccessOrExit(err);
    }

    if (NetworkType != kNetworkType_NotSpecified)
    {
        err = writer.Put(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_NetworkType), (uint32_t) NetworkType);
        SuccessOrExit(err);
    }

    if (mWiFi.WiFiSSID[0] != 0)
    {
        err = writer.PutString(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_WiFiSSID), mWiFi.WiFiSSID);
        SuccessOrExit(err);
    }

    if (mWiFi.WiFiMode != kWiFiMode_NotSpecified)
    {
        err = writer.Put(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_WiFiMode), (uint32_t) mWiFi.WiFiMode);
        SuccessOrExit(err);
    }

    if (mWiFi.WiFiRole != kWiFiRole_NotSpecified)
    {
        err = writer.Put(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_WiFiRole), (uint32_t) mWiFi.WiFiRole);
        SuccessOrExit(err);
    }

    if (mWiFi.WiFiSecurityType != kWiFiSecurityType_NotSpecified)
    {
        err = writer.Put(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_WiFiSecurityType), (uint32_t) mWiFi.WiFiSecurityType);
        SuccessOrExit(err);
    }

    if (mWiFi.WiFiKeyLen != 0)
    {
        err = writer.PutBytes(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_WiFiPreSharedKey), mWiFi.WiFiKey, mWiFi.WiFiKeyLen);
        SuccessOrExit(err);
    }

    if (mWiFi.WirelessSignalStrength != INT16_MIN)
    {
        err = writer.Put(ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_WirelessSignalStrength), mWiFi.WirelessSignalStrength);
        SuccessOrExit(err);
    }

    err = writer.EndContainer(outerContainer);
    SuccessOrExit(err);

exit:
    return err;
}

WEAVE_ERROR NetworkInfo::Decode(nl::Weave::TLV::TLVReader & reader)
{
    WEAVE_ERROR err;
    TLVType outerContainer;
    uint32_t val;

    if (reader.GetType() == kTLVType_NotSpecified)
    {
        err = reader.Next();
        SuccessOrExit(err);
    }

    VerifyOrExit(reader.GetTag() == ProfileTag(kWeaveProfile_NetworkProvisioning, kTag_NetworkInformation) ||
                 reader.GetTag() == AnonymousTag,
                 err = WEAVE_ERROR_INVALID_TLV_ELEMENT);

    VerifyOrExit(reader.GetType() == kTLVType_Structure, err = WEAVE_ERROR_WRONG_TLV_TYPE);

    err = reader.EnterContainer(outerContainer);
    SuccessOrExit(err);

    Reset();

    while ((err = reader.Next()) == WEAVE_NO_ERROR)
    {
        uint64_t elemTag = reader.GetTag();

        if (!IsProfileTag(elemTag) || ProfileIdFromTag(elemTag) != kWeaveProfile_NetworkProvisioning)
            continue;

        switch (TagNumFromTag(elemTag))
        {
        case kTag_NetworkId:
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(NetworkId);
            SuccessOrExit(err);
            NetworkIdPresent = true;
            break;
        case kTag_NetworkType:
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(val);
            SuccessOrExit(err);
            NetworkType = (NetworkType_t) val;
            break;
        case kTag_WirelessSignalStrength:
            VerifyOrExit(reader.GetType() == kTLVType_SignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(mWiFi.WirelessSignalStrength);
            SuccessOrExit(err);
            break;
        case kTag_WiFiSSID:
            VerifyOrExit(reader.GetType() == kTLVType_UTF8String, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.GetString(mWiFi.WiFiSSID, sizeof(mWiFi.WiFiSSID));
            SuccessOrExit(err);
            break;
        case kTag_WiFiMode:
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(val);
            SuccessOrExit(err);
            mWiFi.WiFiMode = (WiFiMode_t) val;
            break;
        case kTag_WiFiRole:
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(val);
            SuccessOrExit(err);
            mWiFi.WiFiRole = (WiFiRole_t) val;
            break;
        case kTag_WiFiPreSharedKey:
            VerifyOrExit(reader.GetType() == kTLVType_ByteString, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            val = reader.GetLength();
            VerifyOrExit(val <= kMaxWiFiKeyLength, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            mWiFi.WiFiKeyLen = (uint16_t)val;
            err = reader.GetBytes(mWiFi.WiFiKey, sizeof(mWiFi.WiFiKey));
            SuccessOrExit(err);
            break;
        case kTag_WiFiSecurityType:
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(val);
            SuccessOrExit(err);
            mWiFi.WiFiSecurityType = (WiFiSecurityType_t) val;
            break;
        case kTag_ThreadNetworkName:
            fprintf(stderr, "name type is %d", reader.GetType());
            VerifyOrExit(reader.GetType() == kTLVType_UTF8String, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.GetString(mThread.mNetworkName, sizeof(mThread.mNetworkName));
            SuccessOrExit(err);
            break;
        case kTag_ThreadExtendedPANId:
            fprintf(stderr, "extpanid type is %d", reader.GetType());
            VerifyOrExit(reader.GetType() == kTLVType_ByteString, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.GetBytes(mThread.mExtendedPANId, sizeof(mThread.mExtendedPANId));
            mThread.mIsExtendedPANIdSet = true;
            SuccessOrExit(err);
            break;
        case kTag_ThreadPANId:
            fprintf(stderr, "panid type is %d", reader.GetType());
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(mThread.mPANId);
            SuccessOrExit(err);
            break;
        case kTag_ThreadChannel:
            fprintf(stderr, "channel type is %d", reader.GetType());
            VerifyOrExit(reader.GetType() == kTLVType_UnsignedInteger, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            err = reader.Get(mThread.mChannel);
            SuccessOrExit(err);
            break;
        case kTag_ThreadNetworkKey:
            fprintf(stderr, "network key type is %d", reader.GetType());
            VerifyOrExit(reader.GetType() == kTLVType_ByteString, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            val = reader.GetLength();
            VerifyOrExit(val <= kMaxWiFiKeyLength, err = WEAVE_ERROR_INVALID_TLV_ELEMENT);
            mWiFi.WiFiKeyLen = (uint16_t)val;
            err = reader.GetBytes(mThread.mNetworkKey, sizeof(mThread.mNetworkKey));
            SuccessOrExit(err);
            break;
        default:
            // Ignore unknown elements for compatibility with future formats.
            break;
        }
    }

    if (err != WEAVE_END_OF_TLV)
        ExitNow();

    err = reader.ExitContainer(outerContainer);
    SuccessOrExit(err);

exit:
    return err;
}

WEAVE_ERROR NetworkInfo::MergeTo(NetworkInfo & dest)
{
    if (NetworkType != kNetworkType_NotSpecified)
    {
        dest.NetworkType = NetworkType;
    }
    if (NetworkIdPresent)
    {
        dest.NetworkId = NetworkId;
        dest.NetworkIdPresent = true;
    }
    if (mWiFi.WiFiSSID[0] != 0)
    {
        memcpy(dest.mWiFi.WiFiSSID, mWiFi.WiFiSSID, sizeof(mWiFi.WiFiSSID));
    }
    if (mWiFi.WiFiMode != kWiFiMode_NotSpecified)
    {
        dest.mWiFi.WiFiMode = mWiFi.WiFiMode;
    }
    if (mWiFi.WiFiRole != kWiFiRole_NotSpecified)
    {
        dest.mWiFi.WiFiRole = mWiFi.WiFiRole;
    }
    if (mWiFi.WiFiSecurityType != kWiFiSecurityType_NotSpecified)
    {
        dest.mWiFi.WiFiSecurityType = mWiFi.WiFiSecurityType;
    }
    if (mWiFi.WiFiKeyLen != 0)
    {
        memcpy(dest.mWiFi.WiFiKey, mWiFi.WiFiKey, mWiFi.WiFiKeyLen);
        dest.mWiFi.WiFiKeyLen = mWiFi.WiFiKeyLen;
    }
    if (mWiFi.WirelessSignalStrength != INT16_MIN)
    {
        dest.mWiFi.WirelessSignalStrength = mWiFi.WirelessSignalStrength;
    }

    return WEAVE_NO_ERROR;
}


WEAVE_ERROR NetworkInfo::EncodeArray(nl::Weave::TLV::TLVWriter & writer, const NetworkInfo * elems, size_t count)
{
    WEAVE_ERROR err;
    TLVType outerContainerType;

    err = writer.StartContainer(AnonymousTag, kTLVType_Array, outerContainerType);
    SuccessOrExit(err);

    for (size_t i = 0; i < count; i++)
    {
        err = elems[i].Encode(writer);
        SuccessOrExit(err);
    }

    err = writer.EndContainer(outerContainerType);
    SuccessOrExit(err);

exit:
    return err;
}

} // namespace Internal
} // namespace DeviceLayer
} // namespace Weave
} // namespace nl
