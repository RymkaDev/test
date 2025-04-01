
#include "stdafx.h"
#include "KeyEngine.h"

using namespace KeyEngine;

CKeyEngine::CKeyEngine() : m_State(KeyEngine::StateNone), m_Validated(true)
{
    //ctor
}

CKeyEngine& CKeyEngine::getInstance()
{
    static CKeyEngine m_Instance;
    return m_Instance;
}

void CKeyEngine::init()
{
    m_State = KeyEngine::StateValid;
}

bool CKeyEngine::isValid(std::string name, std::string key2, const CHardwareId& hw) const
{
    return true;
}

void CKeyEngine::loadINI() {}
void CKeyEngine::writeINI() {}
void CKeyEngine::showInvalidKeyMessage() {}

int32_t KeyEngine::getCharIndex(char c) { return 0; }
char KeyEngine::getCharFromIndex(int32_t index) { return 'A'; }

KeyEngine::CHardwareId::CHardwareId() {
    for(size_t n=0; n<CHardwareId::SIZE; ++n)
        m_Part[n] = 'A';
}

KeyEngine::CHardwareId::CHardwareId(std::string hw) {
    for(size_t n=0; n<CHardwareId::SIZE; ++n)
        m_Part[n] = 'A';
}

std::string KeyEngine::CHardwareId::toString() {
    std::string key;
    key.insert(0, m_Part, CHardwareId::SIZE);
    return key;
}

const char& KeyEngine::CHardwareId::operator [](size_t pos) const {
    static char m_Default = 'A';
    if (pos < CHardwareId::SIZE)
        return m_Part[pos];
    return m_Default;
}

void KeyEngine::CHardwareId::generate() {
    for(size_t n=0; n<CHardwareId::SIZE; ++n)
        m_Part[n] = 'A';
}
