// Simple Program to calculate fibonacci of input

package main

import "fmt"

func FibonacciRecursion(n int) int {
	if n <= 1 {
		return n
	}
	return FibonacciRecursion(n-1) + FibonacciRecursion(n-2)
}

func main() {
	fmt.Print("Enter number : ")
	var n int
	fmt.Scanln(&n)

	fmt.Println("Fibonacci of", n, "is", FibonacciRecursion(n))
}
