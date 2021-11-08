/*  This file is part of steamstub_unpack.

    steamstub_unpack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS
    OR IMPLIED WARRANTY. IN NO EVENT WILL THE AUTHORS BE HELD
    LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.  */

#include <iostream>

#include <LIEF/LIEF.hpp>
#include <mio/mmap.hpp>
#include <ppk_assert.h>
#include <Zydis/Zydis.h>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

struct steamstub_header {
    uint32_t xor_key;
    uint32_t signature;

    uint64_t imagebase;
    uint64_t ep_addr;

    uint32_t bind_offset;
    uint32_t __pad1;

    uint64_t oep_addr;

    uint32_t __pad2;
    uint32_t payload_size;
    uint32_t drmpdll_off;
    uint32_t drmpdll_size;
    uint32_t appid;
    uint32_t flags;
    uint32_t bind_vsize;
    uint32_t __pad3;

    uint64_t code_addr;
    uint64_t code_rawsize;

    uint8_t aes_key[0x20];
    uint8_t aes_iv[0x10];
    uint8_t code_section_stolen[0x10];
    uint32_t drmp_encrypt_keys[0x4];
    uint32_t __pad4[0x8];

    uint64_t GetModuleHandleA_rva;
    uint64_t GetModuleHandleW_rva;
    uint64_t LoadLibraryA_rva;
    uint64_t LoadLibraryW_rva;
    uint64_t GetProcAddress_rva;
};

#define STUB_FLAG_NoModuleVerification 0x02
#define STUB_FLAG_NoEncryption 0x04
#define STUB_FLAG_NoOwnershipCheck 0x10
#define STUB_FLAG_NoDebuggerCheck 0x20
#define STUB_FLAG_NoErrorDialog 0x40

bool
parse_args (int argc,
            char **argv,
            std::string_view &out_input,
            std::string_view &out_output)
{
    while (true) {
        switch (getopt(argc, argv, "i:o:h")) {
            case 'i':
                out_input = optarg;
                continue;
            case 'o':
                out_output = optarg;
                continue;
            case '?':
            case 'h':
            default :
                std::cout << "Usage: steamstub_unpack -i packed.exe -o unpacked.exe";
                return false;
            case -1:
                break;
        }
        break;
    }

    bool success = true;

    if (out_input.empty()) {
        std::cerr << "Missing argument: input\n";
        success = false;
    }

    if (out_output.empty()) {
        std::cerr << "Missing argument: output\n";
        success = false;
    }

    if (!success) {
        std::cerr << "See 'steamstub_unpack -h' for help\n";
    }

    return success;
}

int
main (int argc,
      char **argv)
{
    using namespace LIEF::PE;

    std::string_view input_path, output_path;
    if (!parse_args(argc, argv, input_path, output_path)) {
        return EXIT_FAILURE;
    }

    auto bin = Parser::parse(input_path.data());

    enum {
        x64, x86
    } arch;

    if (bin->header().machine() == MACHINE_TYPES::IMAGE_FILE_MACHINE_AMD64) {
        arch = x64;
    }
    else if (bin->header().machine() == MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) {
        arch = x86;
    }
    else {
        std::cerr << "[-] invalid architecture\n";
        return EXIT_FAILURE;
    }

    auto s_containing_ep = bin->section_from_offset(bin->va_to_offset(bin->entrypoint()));

    PPK_ASSERT_ERROR(s_containing_ep.name() == ".bind");

    ZydisDecoder decoder;
    arch == x64 ?
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64) :
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

    size_t offset = -1;

    {
        auto v_func_bytes = bin->get_content_from_virtual_address(bin->entrypoint(), arch == x64 ? 0x5F : 0x36);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        uint8_t n = 0;
        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_CALL &&
                ++n > 1 &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr,
                                                      &instr.operands[0],
                                                      bin->entrypoint() + (data - v_func_bytes.data()),
                                                      &offset)))
            {
                break;
            }

            data += instr.length;
            length -= instr.length;
        }
    }

    PPK_ASSERT_ERROR(offset != -1);

    {
        auto v_func_bytes = bin->get_content_from_virtual_address(offset, arch == x64 ? 0x36 : 0x29);

        uint8_t *data = v_func_bytes.data();
        size_t length = v_func_bytes.size();

        uint8_t n = 0;
        size_t imm = -1;
        ZydisDecodedInstruction instr;
        while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, length, &instr))) {
            if (instr.mnemonic == ZYDIS_MNEMONIC_MOV && ++n > 1) {
                imm = instr.operands[1].imm.value.u;
                break;
            }

            data += instr.length;
            length -= instr.length;
        }

        PPK_ASSERT_ERROR(imm == 0xF0);
    }

    auto v_stubheader = bin->get_content_from_virtual_address(bin->entrypoint() - 0xF0, 0xF0);
    uint32_t key = *(uint32_t *)(v_stubheader.data());
    uint8_t *data = v_stubheader.data() + sizeof(uint32_t);
    while (data < v_stubheader.data() + v_stubheader.size()) {
        auto val = *(uint32_t *)(data);
        *(uint32_t *)(data) = val ^ key;
        key = val;
        data += sizeof(uint32_t);
    }

    auto *stubheader = (steamstub_header *)(v_stubheader.data());

    PPK_ASSERT_ERROR(stubheader->signature == 0xC0DEC0DF);

    std::cout << "[+] appid: " << stubheader->appid << "\n";

    bool noencrypt = (stubheader->flags & STUB_FLAG_NoEncryption) == STUB_FLAG_NoEncryption;
    if (!noencrypt) {
        using namespace CryptoPP;

        auto s_text = bin->get_section(".text");

        // no idea how to force LIEF to ignore section header size, so we just mmap that memory region ourselves
        mio::mmap_source raw_text_mmap(input_path, s_text.pointerto_raw_data(), s_text.sizeof_raw_data());
        const auto *stolen_start = &stubheader->code_section_stolen[0];
        const auto *stolen_end = stolen_start + sizeof(stubheader->code_section_stolen);

        std::vector<uint8_t> v_code_bytes;
        v_code_bytes.insert(v_code_bytes.begin(), stolen_start, stolen_end);
        v_code_bytes.insert(v_code_bytes.end(), raw_text_mmap.begin(), raw_text_mmap.end());

        {
            ECB_Mode<AES>::Decryption decryption(stubheader->aes_key, sizeof(stubheader->aes_key));
            decryption.ProcessData(stubheader->aes_iv, stubheader->aes_iv, sizeof(stubheader->aes_iv));
        }

        {
            CBC_Mode<AES>::Decryption  decryption(stubheader->aes_key, sizeof(stubheader->aes_key), stubheader->aes_iv);
            decryption.ProcessData(v_code_bytes.data(), v_code_bytes.data(), v_code_bytes.size());
        }

        s_text.content(v_code_bytes);
        bin->remove_section(".text");
        bin->add_section(s_text);
    }

    bin->optional_header().addressof_entrypoint(stubheader->oep_addr);
    bin->remove_section(".bind");
    bin->write(output_path.data());

    std::cout << "[+] unpacked\n";

    return EXIT_SUCCESS;
}
