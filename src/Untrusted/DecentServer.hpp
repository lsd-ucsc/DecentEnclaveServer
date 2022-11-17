// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <iostream>

#include <DecentEnclave/Common/Sgx/Exceptions.hpp>
#include <DecentEnclave/Common/Sgx/IasRequester.hpp>
#include <DecentEnclave/Untrusted/Sgx/DecentSgxEnclave.hpp>

#include "../Enclave_u.h"

namespace DecentEnclaveServer
{

class DecentServer :
	public DecentEnclave::Untrusted::Sgx::DecentSgxEnclave
{
public: // static members:


	using Base = DecentEnclave::Untrusted::Sgx::DecentSgxEnclave;


public:

	DecentServer(
		const sgx_spid_t& spid,
		std::unique_ptr<DecentEnclave::Common::Sgx::IasRequester> iasReq,
		const std::string& enclaveImgPath = DECENT_ENCLAVE_PLATFORM_SGX_IMAGE,
		const std::string& launchTokenPath = DECENT_ENCLAVE_PLATFORM_SGX_TOKEN
	) :
		Base(enclaveImgPath, launchTokenPath),
		m_spid(spid),
		m_iasReq(std::move(iasReq))
	{}

	virtual ~DecentServer() = default;

	void Init()
	{
		sgx_status_t funcRet = SGX_ERROR_UNEXPECTED;
		sgx_status_t edgeRet = ecall_decent_server_init(
			m_encId,
			&funcRet,
			m_encId,
			&m_spid,
			m_iasReq.get()
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			edgeRet,
			ecall_decent_server_init
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			funcRet,
			ecall_decent_server_init
		);
	}

private:

	sgx_spid_t m_spid;
	std::unique_ptr<DecentEnclave::Common::Sgx::IasRequester> m_iasReq;
}; // class DecentServer

} // namespace DecentEnclaveServer
