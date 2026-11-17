#include "codec.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include "schema.inc"
static void json_string(const std::string &text) {
    std::cout << '"';
    for (unsigned char byte : text) {
        if (byte == '"' || byte == '\\') {
            std::cout << '\\' << static_cast<char>(byte);
        } else if (byte < 32) {
            std::cout << "\\u00" << std::hex << std::setfill('0') << std::setw(2) << unsigned(byte);
        } else {
            std::cout << static_cast<char>(byte);
        }
    }
    std::cout << std::dec << '"';
}

static void json_value(const rax::smir::records::Value &value) {
    using rax::smir::records::Tag;
    switch (value.tag) {
    case Tag::Unsigned: std::cout << value.number; break;
    case Tag::Signed: std::cout << std::bit_cast<std::int64_t>(value.number); break;
    case Tag::Boolean: std::cout << (value.number ? "true" : "false"); break;
    case Tag::Text: json_string(value.data); break;
    case Tag::Bytes: {
        const char *digits = "0123456789abcdef";
        std::string hex;
        for (unsigned char byte : value.data) {
            hex += digits[byte >> 4];
            hex += digits[byte & 15];
        }
        json_string(hex);
        break;
    }
    case Tag::Option:
        if (value.elements.empty()) std::cout << "null";
        else {
            std::cout << "{\"some\":";
            json_value(value.elements[0]);
            std::cout << '}';
        }
        break;
    case Tag::Vector:
        std::cout << '[';
        for (std::size_t index = 0; index < value.elements.size(); ++index) {
            if (index) std::cout << ',';
            json_value(value.elements[index]);
        }
        std::cout << ']';
        break;
    case Tag::Record:
        std::cout << '{';
        for (std::size_t index = 0; index < value.fields.size(); ++index) {
            if (index) std::cout << ',';
            json_string(value.fields[index].first);
            std::cout << ':';
            json_value(value.fields[index].second);
        }
        std::cout << '}';
        break;
    }
}


int main(int argc,char **argv) {
 if(argc!=3)return 3;
 std::ifstream input(argv[2],std::ios::binary);if(!input)return 3;
 std::vector<std::uint8_t> bytes;char chunk[4096];constexpr std::size_t limit=16*1024*1024;
 while(input && bytes.size()<=limit){const auto n=std::min(sizeof(chunk),limit+1-bytes.size());input.read(chunk,n);bytes.insert(bytes.end(),chunk,chunk+input.gcount());}
 if(input.bad())return 3;
 try {
  std::string kind=argv[1];
  if(kind=="root3"){
   if(bytes.size()<4)throw rax::smir::records::Error("V3-REVISION-TRUNCATED");
   std::uint32_t rev=0;for(unsigned i=0;i<4;++i)rev|=std::uint32_t(bytes[i])<<(i*8);
   if(rev!=2 && rev!=3)throw rax::smir::records::Error("V3-REVISION");
   kind=rev==2?"execution_functions":"execution_functions_v3";
  }
  rax::smir::records::Limits limits;limits.depth=128;
  const rax::smir::records::Codec codec(smir_test_schema,limits);
  const auto value=codec.decode(kind,bytes);
  if(codec.encode(kind,value)!=bytes)return 4;
  json_value(value);std::cout<<'\n';return 0;
 }catch(const std::exception &e){std::cout<<e.what()<<'\n';return 2;}
}
