################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/lib/kernel/bitmap.c \
../src/lib/kernel/console.c \
../src/lib/kernel/debug.c \
../src/lib/kernel/hash.c \
../src/lib/kernel/list.c 

OBJS += \
./src/lib/kernel/bitmap.o \
./src/lib/kernel/console.o \
./src/lib/kernel/debug.o \
./src/lib/kernel/hash.o \
./src/lib/kernel/list.o 

C_DEPS += \
./src/lib/kernel/bitmap.d \
./src/lib/kernel/console.d \
./src/lib/kernel/debug.d \
./src/lib/kernel/hash.d \
./src/lib/kernel/list.d 


# Each subdirectory must supply rules for building sources it contributes
src/lib/kernel/%.o: ../src/lib/kernel/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


