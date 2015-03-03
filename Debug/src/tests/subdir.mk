################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/arc4.c \
../src/tests/cksum.c \
../src/tests/lib.c \
../src/tests/main.c 

OBJS += \
./src/tests/arc4.o \
./src/tests/cksum.o \
./src/tests/lib.o \
./src/tests/main.o 

C_DEPS += \
./src/tests/arc4.d \
./src/tests/cksum.d \
./src/tests/lib.d \
./src/tests/main.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/%.o: ../src/tests/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


