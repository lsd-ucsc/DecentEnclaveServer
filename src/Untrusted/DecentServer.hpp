// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <DecentEnclave/Common/Sgx/Exceptions.hpp>
#include <DecentEnclave/Common/Sgx/IasRequester.hpp>
#include <DecentEnclave/Untrusted/DecentEnclaveBase.hpp>
#include <DecentEnclave/Untrusted/Sgx/SgxEnclave.hpp>


extern "C" sgx_status_t ecall_decent_common_init(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	const uint8_t* auth_list,
	size_t auth_list_size
);


extern "C" sgx_status_t ecall_decent_server_init(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	const sgx_spid_t* spidPtr,
	void* iasRequesterPtr
);


extern "C" sgx_status_t ecall_decent_server_lambda_handler(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	void* sock_ptr
);


namespace DecentEnclaveServer
{


class DecentServer :
	public DecentEnclave::Untrusted::Sgx::SgxEnclave,
	virtual public DecentEnclave::Untrusted::DecentEnclaveBase
{
public: // static members:

	using EncBase = DecentEnclave::Untrusted::DecentEnclaveBase;
	using SgxBase = DecentEnclave::Untrusted::Sgx::SgxEnclave;

public:

	DecentServer(
		const sgx_spid_t& spid,
		std::unique_ptr<DecentEnclave::Common::Sgx::IasRequester> iasReq,
		const std::vector<uint8_t>& authList,
		const std::string& enclaveImgPath = DECENT_ENCLAVE_PLATFORM_SGX_IMAGE,
		const std::string& launchTokenPath = DECENT_ENCLAVE_PLATFORM_SGX_TOKEN
	) :
		SgxBase(enclaveImgPath, launchTokenPath),
		m_spid(spid),
		m_iasReq(std::move(iasReq))
	{
		DECENTENCLAVE_SGX_ECALL_CHECK_ERROR_E_R(
			ecall_decent_common_init,
			m_encId,
			authList.data(),
			authList.size()
		);

		DECENTENCLAVE_SGX_ECALL_CHECK_ERROR_E_R(
			ecall_decent_server_init,
			m_encId,
			&m_spid,
			m_iasReq.get()
		);
	}

	virtual ~DecentServer() = default;

#ifdef _MSC_VER
// mitigating MSVC compiler bug:
// https://stackoverflow.com/questions/469508/visual-studio-compiler-warning-c4250-class1-inherits-class2member-via-d
// https://stackoverflow.com/questions/6864550/c-inheritance-via-dominance-warning
	virtual const char* GetPlatformName() const override
	{
		return SgxBase::GetPlatformName();
	}
#else // _MSC_VER
	using SgxBase::GetPlatformName;
#endif // _MSC_VER

	virtual void HandleCall(
		std::unique_ptr<EncBase::LmdFuncBase::SocketType> sock
	) override
	{
		sgx_status_t funcRet = SGX_ERROR_UNEXPECTED;
		sgx_status_t edgeRet = ecall_decent_server_lambda_handler(
			m_encId,
			&funcRet,
			sock.get()
		);
		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			edgeRet,
			ecall_decent_server_lambda_handler
		);

		// call is successfully made to the enclave side
		// now it's relative safe to release the ownership of the socket.
		sock.release();

		DECENTENCLAVE_CHECK_SGX_RUNTIME_ERROR(
			funcRet,
			ecall_decent_server_lambda_handler
		);
	}

	virtual void Heartbeat() override
	{
		throw std::runtime_error("Not supported");
	}

private:

	sgx_spid_t m_spid;
	std::unique_ptr<DecentEnclave::Common::Sgx::IasRequester> m_iasReq;
}; // class DecentServer


} // namespace DecentEnclaveServer
