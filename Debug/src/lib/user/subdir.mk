################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/lib/user/console.c \
../src/lib/user/debug.c \
../src/lib/user/entry.c \
../src/lib/user/syscall.c 

OBJS += \
./src/lib/user/console.o \
./src/lib/user/debug.o \
./src/lib/user/entry.o \
./src/lib/user/syscall.o 

C_DEPS += \
./src/lib/user/console.d \
./src/lib/user/debug.d \
./src/lib/user/entry.d \
./src/lib/user/syscall.d 


# Each subdirectory must supply rules for building sources it contributes
src/lib/user/%.o: ../src/lib/user/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


