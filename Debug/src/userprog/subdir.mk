################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/userprog/exception.c \
../src/userprog/gdt.c \
../src/userprog/pagedir.c \
../src/userprog/process.c \
../src/userprog/syscall.c \
../src/userprog/tss.c 

OBJS += \
./src/userprog/exception.o \
./src/userprog/gdt.o \
./src/userprog/pagedir.o \
./src/userprog/process.o \
./src/userprog/syscall.o \
./src/userprog/tss.o 

C_DEPS += \
./src/userprog/exception.d \
./src/userprog/gdt.d \
./src/userprog/pagedir.d \
./src/userprog/process.d \
./src/userprog/syscall.d \
./src/userprog/tss.d 


# Each subdirectory must supply rules for building sources it contributes
src/userprog/%.o: ../src/userprog/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


