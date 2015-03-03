################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/lib/arithmetic.c \
../src/lib/debug.c \
../src/lib/random.c \
../src/lib/stdio.c \
../src/lib/stdlib.c \
../src/lib/string.c \
../src/lib/ustar.c 

OBJS += \
./src/lib/arithmetic.o \
./src/lib/debug.o \
./src/lib/random.o \
./src/lib/stdio.o \
./src/lib/stdlib.o \
./src/lib/string.o \
./src/lib/ustar.o 

C_DEPS += \
./src/lib/arithmetic.d \
./src/lib/debug.d \
./src/lib/random.d \
./src/lib/stdio.d \
./src/lib/stdlib.d \
./src/lib/string.d \
./src/lib/ustar.d 


# Each subdirectory must supply rules for building sources it contributes
src/lib/%.o: ../src/lib/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


