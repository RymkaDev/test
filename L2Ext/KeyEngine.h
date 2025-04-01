
#pragma once

#include <string>

namespace KeyEngine
{
    class CHardwareId
    {
    public:
        enum { SIZE = 8 };

        CHardwareId();
        CHardwareId(std::string hw);

        std::string toString();
        const char& operator[](size_t pos) const;
        void generate();

    private:
        char m_Part[SIZE];
    };

    class CKeyEngine
    {
    public:
        enum State
        {
            StateNone,
            StateInvalid,
            StateValid
        };

        static CKeyEngine& getInstance();

        void init();
        bool isValid(std::string name, std::string key, const CHardwareId& hw) const;

    private:
        CKeyEngine();

        void loadINI();
        void writeINI();
        void showInvalidKeyMessage();

        mutable bool m_Validated;
        std::string m_Name;
        std::string m_Key;
        CHardwareId m_Hardware;
        State m_State;
    };

    int32_t getCharIndex(char c);
    char getCharFromIndex(int32_t index);
} // namespace KeyEngine
