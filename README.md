# Polymorphic-engine
A polymorphic engine made as a project for Information Systems Security class, written in Go. The goal is to provide polymorphic functionality to any executable PE file. This project is purely for educational purposes!

This engine is for academic purposes only!

PolymorphicEngine is a 2 piece software whose main purpose is to pack executables and make them harder to reverse and detect. This software consists of two equaly important parts. 

Engine's main purpose is to load a payload, generate a key, encrypt and append the initial encrypted version of payload to the end of a packer. Packer on the other hand has mechanisms to load it's appended payload, guess the key (to make reversing the binary a "bit" more complicated), decrypt, load the executable, encrypt it and in the end save it as such (encrypted with new key). 

This product was intended for usage on Windows operating systems
How to use:

## Dependencies

* gcc, g++ compiler
* Golang

## Usage

1. Run buildAndRun.bat script (open it, configure, save and run) 
2. 2. Build all files manually via go Build 

In case you picked option 1. the script should attach the payload and the packer should be packed and ready to be dispatched. 
Otherwise:

1. Run attacher.exe (or whatever the output name of engine.go is) 
   * attacher.exe takes in 2 arguments in plain text format. First argument is the full path to payload. Second argument is path to packer.
     *Packer is what we call output of PolymorphicEngine.go*
2. The packer should be ready for dispatch.

Known issues: *In current version MemoryModule is not working as intended and the payload is being written on disk and executed. This practicaly ruins the whole purpose as the payload can be detected very easily once it's been written to the disk. Currently the packer creates another copy of itself and attaches another encrypted version of payload but unfortunately the files don't delete eachother.*