//
// Created by valer on 2024/4/14.
//


/*
 *  https://github.com/WhiteFoxLinux/DataVault
 *  Code from Mr. vAlerain
 *  Invented to solve the problem of data that cannot be stored for long and long in C++
 */
#ifndef DATAVAULT_DATAVAULT_H
#define DATAVAULT_DATAVAULT_H

#endif //DATAVAULT_DATAVAULT_H

#include <iostream>
class DataVault {
private:
    int value; //

public:
    // Constructor, used to initialize variable values
    void CustomVariable(int val) {
        value = val;
    }

    //Define variables

    int getValue() {
        return value;
    }

    // Method for setting variable values
    void setValue(int val) {
        value = val;
    }
};
